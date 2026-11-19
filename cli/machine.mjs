// agent-bot machine <pair|unpair|status|attest> and top-level `agent-bot pair|unpair`
// (#1254, #1295): pairing between this account's agent-daemon and the local
// agent-machine daemon (or `pair comms` for the agent-comms broker). Pair and
// unpair change machine-level trust and go through the owner gate like
// every other owner action; status is read-only.
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { existsSync } from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { assertOwnerAction } from '../owner-action.mjs';
import { reviewHQServiceRecovery } from '../machine-service-recovery.mjs';
import { openFirstHQReview } from '../machine-first-hq-review.mjs';
import { machineOwnerPresence, ServerSession } from '../identity-cli.mjs';
import {
  AGENT_MACHINE_DIR, buildRequest, machineCall, machineSocketPath,
  daemonFingerprint, loadMachineSigner, loadOrCreateMachineKey, loadMachinePublicKey, pairedPublicKey, pinDaemonPub, verifyResponse,
  writeAgentDaemonPeer, unpairAgentDaemon, machineStateDir,
} from '../machine-client.mjs';

const USAGE = `usage: agent-bot machine <command> | agent-bot pair [--repin] | agent-bot unpair
  pair [--repin]               trust this account's agent-daemon key with agent-machine and pin daemon.pub
  pair comms [--broker NAME]   pair this daemon with the agent-comms broker (alias for daemon pair-comms)
  owner-public-key             print the protected macOS owner approval public key as JSON
  review-hq-service-recovery FILE --machine-fingerprint SHA256
                             review one paired HQ service repair and print its owner proof
  review-first-hq FILE         review one transferred first-HQ plan in a temporary local Approvals page
  approve-pairing              approve a Machine challenge from stdin and print its signed proof as JSON
  attest                       attest the existing local pairing to this device's enrolled Harbor
  unpair                       revoke the agent-daemon peer and drop the daemon.pub pin
  status                       show pairing state, then a signed agent-machine status round trip when paired`;

async function statusRoundTrip({ home, env, socketPath = machineSocketPath({ home, env }), connectImpl }) {
  const pinned = pairedPublicKey({ env, home });
  const signer = loadOrCreateMachineKey({ env, home });
  const request = buildRequest({ verb: 'status' }, signer);
  const line = await machineCall({ socketPath, request, ...(connectImpl ? { connectImpl } : {}) });
  return verifyResponse(line, pinned, { expectedNonce: request.nonce });
}

// Harbor's pairing protocol binds one local status round trip to the enrolled
// device, its pinned machine key, and a single-use server challenge.
async function attest({ env, home, gate, socketPath, connectImpl, session = new ServerSession({ env, home }) }) {
  const device = session.device();
  await gate(`machine attest existing local pairing for ${device.device_id} to ${device.server}`, { env, home });
  const signer = loadMachineSigner({ env, home });
  if (!signer) throw new Error('this account has no existing agent-daemon pairing key');
  const pinned = pairedPublicKey({ env, home });
  if (pinned.length !== 32 || pinned.equals(signer.publicKeyRaw)) throw new Error('invalid pinned machine key');
  const deviceId = device.device_id;
  const machineKey = pinned.toString('base64');
  const daemonId = daemonFingerprint(signer.publicKeyRaw).slice(0, 16);
  const machineId = daemonFingerprint(pinned).slice(0, 16);
  const route = '/api/daemon/pairing';
  async function call(method, path, payload) {
    const reply = await session.call(method, path, payload, { requireRequestNonce: true });
    if (reply.device_id !== deviceId) throw new Error('Harbor replied for a different enrolled device');
    return reply;
  }
  function checkReceipt(receipt) {
    if (receipt.state !== 'attested' || receipt.daemon_key_id !== daemonId || receipt.machine_key_id !== machineId) {
      throw new Error('Harbor did not confirm this device and its existing local pairing keys');
    }
    return receipt;
  }

  const current = await call('GET', route);
  if (current.state === 'attested') return checkReceipt(current);
  if (current.state !== 'none') throw new Error(`Harbor pairing state is ${current.state}, expected none`);
  const { challenge } = await call('POST', route + '/challenge');
  if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(challenge)) throw new Error('invalid Harbor pairing challenge');
  const binding = ['agent-bot-pairing/1', deviceId, challenge, machineKey, ''].join('\n');
  const nonce = 'abp1.' + createHash('sha256').update(binding).digest('base64url');
  const request = buildRequest({ verb: 'status' }, signer, { nonce });
  const line = await machineCall({ socketPath: socketPath ?? machineSocketPath({ env, home }), request, connectImpl });
  const reply = verifyResponse(line, pinned, { expectedNonce: nonce });
  if (reply.ok !== true) throw new Error('agent-machine refused the signed status request');

  // Go signs the literal JSON bytes of the status body, including its escaping.
  const fields = JSON.stringify({ challenge, machine_key: machineKey, request });
  const payload = fields.slice(0, -1) + ',"response":' + line + '}';
  let receipt;
  try {
    receipt = await call('POST', route, payload);
  } catch (error) {
    if (!error.ambiguous) throw error;
    const observed = await call('GET', route);
    if (observed.state !== 'attested') throw error;
    receipt = observed;
  }
  return checkReceipt(receipt);
}

export async function runMachineCli(argv = process.argv.slice(2), {
  env = process.env,
  home = homedir(),
  stdout = process.stdout,
  stderr = process.stderr,
  gate = assertOwnerAction,
  ownerPresence = machineOwnerPresence,
  firstHQReview = openFirstHQReview,
  recoveryReview = reviewHQServiceRecovery,
  socketPath,
  connectImpl,
  session,
} = {}) {
  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h' || rest.includes('--help') || rest.includes('-h')) {
    stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (command === 'review-hq-service-recovery') {
    if (rest.length !== 3 || rest[1] !== '--machine-fingerprint' || !rest[0] || rest[0].startsWith('-')) {
      stderr.write(USAGE + '\n');
      return 1;
    }
    let proof;
    await gate('machine-review-hq-service-recovery', {
      env, consent: async () => {
        proof = await recoveryReview(rest[0], rest[2], { env, home, display: stderr });
        return proof;
      },
    });
    if (!proof) { stderr.write('Service repair discarded.\n'); return 1; }
    stdout.write(JSON.stringify(proof) + '\n');
    return 0;
  }
  if (command === 'review-first-hq') {
    if (rest.length !== 1 || !rest[0] || rest[0].startsWith('-')) { stderr.write(USAGE + '\n'); return 1; }
    const result = await gate('machine-review-first-hq', { env, consent: () => firstHQReview(rest[0], { env, home }) });
    stdout.write(`First-HQ review ${result}.\n`);
    return result === 'approved' ? 0 : 1;
  }
  if (command === 'owner-public-key' || command === 'approve-pairing') {
    if (rest.length) {
      stderr.write(`${USAGE}\n`);
      return 1;
    }
    const reply = await gate(`machine-${command}`, {
      env, consent: () => ownerPresence(command, { env, home }),
    });
    stdout.write(reply.trimEnd() + '\n');
    return 0;
  }
  if (command === 'pair') {
    const repin = rest.includes('--repin');
    const unexpected = rest.filter((arg) => arg !== '--repin' && arg !== 'machine');
    if (unexpected.length > 0) {
      stderr.write(`${USAGE}\n`);
      return 1;
    }
    await gate('machine-pair', { env });
    if (!existsSync(AGENT_MACHINE_DIR(home, { env }))) {
      throw new Error(`${AGENT_MACHINE_DIR(home, { env })} does not exist — install and start agent-machine first (managed-machine daemon install) [machine-not-running]`);
    }
    const key = loadOrCreateMachineKey({ env, home });
    const peer = writeAgentDaemonPeer({ home, publicKeyRaw: key.publicKeyRaw, env });
    const pin = pinDaemonPub({ env, home, repin });
    if (pin.replaced) stdout.write(`daemon.pub changed: ${pin.replaced} -> ${pin.fingerprint}\n`);
    stdout.write(`agent-machine pinned: sha256 ${pin.fingerprint}\n`);
    stdout.write(`public: ${peer.publicHex}\n`);
    stdout.write(`fingerprint: ${peer.fingerprint}\n`);
    if (!peer.staged) {
      stdout.write(`As the prefix owner run:\n${peer.enroll}\n`);
      return 0;
    }
    const reply = await statusRoundTrip({ home, env, ...(socketPath ? { socketPath } : {}), ...(connectImpl ? { connectImpl } : {}) });
    if (!reply.ok) throw new Error(`pairing staged but agent-machine refused the status check: ${reply.diagnostic ?? ''} ${reply.message ?? ''}`.trim());
    stdout.write(`paired: agent-machine accepted the agent-daemon key (${reply.state ?? reply.message ?? 'ok'})\n`);
    return 0;
  }
  if (command === 'attest') {
    if (rest.length) {
      stderr.write(`${USAGE}\n`);
      return 1;
    }
    const receipt = await attest({ env, home, gate, socketPath, connectImpl, session });
    stdout.write(`attested device ${receipt.device_id} (agent-daemon ${receipt.daemon_key_id}, agent-machine ${receipt.machine_key_id})\n`);
    return 0;
  }
  if (command === 'unpair') {
    const unexpected = rest.filter((arg) => arg !== 'machine');
    if (unexpected.length > 0) {
      stderr.write(`${USAGE}\n`);
      return 1;
    }
    await gate('machine-unpair', { env });
    const result = unpairAgentDaemon({ env, home });
    if (result.revoked) {
      stdout.write('unpaired: peers/agent-daemon.revoked written and the daemon.pub pin removed\n');
    } else {
      stdout.write('unpaired: daemon.pub pin removed; the daemon still trusts this key until the prefix owner revokes peers/agent-daemon\n');
    }
    return 0;
  }
  if (command === 'status') {
    const dir = AGENT_MACHINE_DIR(home, { env });
    const peers = join(dir, 'peers');
    const pin = join(machineStateDir({ env, home }), 'daemon.pub.pin');
    const pairedFiles = existsSync(peers)
      ? ['.pub', '.next', '.confirm', '.revoked'].filter((suffix) => existsSync(join(peers, `agent-daemon${suffix}`)))
      : [];
    stdout.write(`agent-machine dir: ${existsSync(dir) ? dir : 'absent'}\n`);
    stdout.write(`pin: ${existsSync(pin) ? 'present' : 'absent'}; peer files: ${pairedFiles.length ? pairedFiles.join(', ') : 'none'}\n`);
    if (loadMachinePublicKey({ env, home }) === null) {
      stdout.write('client key: absent\n');
      return 0;
    }
    if (!existsSync(pin)) return 0;
    try {
      const reply = await statusRoundTrip({ home, env, ...(socketPath ? { socketPath } : {}), ...(connectImpl ? { connectImpl } : {}) });
      stdout.write(`status: ${reply.ok ? 'ok' : 'refused'}${reply.state ? ` (${reply.state})` : ''}${reply.diagnostic ? ` [${reply.diagnostic}]` : ''}${reply.message ? ` ${reply.message}` : ''}\n`);
    } catch (error) {
      stdout.write(`status: ${error.message}\n`);
      return 1;
    }
    return 0;
  }
  stderr.write(`${USAGE}\n`);
  return command ? 1 : 0;
}

async function main(argv = process.argv.slice(2)) {
  const code = await runMachineCli(argv);
  if (code !== 0) process.exitCode = code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`agent-bot machine: ${error.message}\n`);
    process.exit(1);
  });
}
