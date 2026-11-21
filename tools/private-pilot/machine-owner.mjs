// Source-checkout tool for the already installed private pilot. No enrollment or pin writes.
import { execFile, execFileSync } from 'node:child_process';
import { createPublicKey, verify } from 'node:crypto';
import { accessSync, closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { runMachineCli } from '../../cli/machine.mjs';
import { ANY_DEVELOPER_ID, keydSignerSetting, loadConfig } from '../../config.mjs';
import { developerIdRequirement } from '../../identity/owner-presence.mjs';
import { openFirstHQReview } from '../../machine-first-hq-review.mjs';
import { firstHQSignedBytes, reviewFirstHQ } from '../../machine-first-hq.mjs';

const app = '/Applications/AgentBotOwnerPresence.app';
const executable = app + '/Contents/MacOS/agent-bot-owner-presence';
const run = promisify(execFile);

function checkInstallPath() {
  for (let p = executable; ; p = dirname(p)) {
    const info = lstatSync(p);
    if (info.uid === process.getuid() || !(p === executable ? info.isFile() : info.isDirectory())) {
      throw new Error('The pilot provider must be installed independently of this account.');
    }
    try {
      accessSync(p, constants.W_OK);
    } catch (e) {
      if (e.code !== 'EACCES' && e.code !== 'EPERM' && e.code !== 'EROFS') throw e;
      if (p === '/') return;
      continue;
    }
    throw new Error('The pilot provider must be read-only to this account.');
  }
}

function pairingBytes(c, now) {
  if (c?.action !== 'machine-pair' || Object.keys(c).length !== 5 ||
      ![c.machine_key, c.hq_key, c.nonce].every(s => typeof s === 'string' && s.length === 64 && /^[a-f0-9]+$/.test(s)) ||
      !Number.isSafeInteger(c.expires_at) || c.expires_at <= now || c.expires_at > now + 120) {
    throw new Error('Invalid Machine pairing challenge.');
  }
  return Buffer.from(['agent-bot-machine-owner/v1', c.action, c.machine_key, c.hq_key, c.nonce, c.expires_at, ''].join('\n'));
}

async function requestProof(command, challenge, options) {
  const result = run(executable, [command], { ...options, timeout: 150000, maxBuffer: 1024 });
  result.child.stdin.on('error', () => {});
  result.child.stdin.end(JSON.stringify(challenge));
  return (await result).stdout;
}

export function pilotProvider(pin, {
  platform = process.platform, checkPath = checkInstallPath, check = execFileSync, sign = requestProof,
} = {}) {
  if (platform !== 'darwin') throw new Error('The existing pilot requires macOS.');
  const point = Buffer.from(pin, 'base64');
  if (point.length !== 65 || point[0] !== 4 || point.toString('base64') !== pin) {
    throw new Error('Supply the existing owner public key independently pinned by Machine.');
  }
  const owner = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
  return async (command, challenge, { env, home, signal }) => {
    let bytes;
    if (command === 'approve-pairing') {
      bytes = pairingBytes(challenge, Math.floor(Date.now() / 1000));
    } else if (command === 'approve-first-hq') {
      reviewFirstHQ(challenge);
      bytes = firstHQSignedBytes(challenge);
    } else {
      throw new Error('Unsupported private pilot operation.');
    }
    const { teamId } = keydSignerSetting(loadConfig({ env, home }));
    if (!teamId || teamId === ANY_DEVELOPER_ID) throw new Error('An exact pilot publisher is required.');
    checkPath();
    const requirement = developerIdRequirement({ teamId, identifier: 'ai.true-line.agent-bot-owner-presence' });
    const options = { env: { PATH: '/usr/bin:/bin', HOME: home }, encoding: 'utf8', timeout: 15000 };
    for (const target of [app, executable]) {
      check('/usr/bin/codesign', ['--verify', '--strict', '-R=' + requirement, target], options);
    }
    check('/usr/sbin/spctl', ['--assess', '--type', 'execute', app], options);
    const reply = JSON.parse(await sign(command, challenge, { ...options, signal }));
    if (reply?.public_key !== pin || Object.keys(reply).length !== 2 || typeof reply.signature !== 'string') {
      throw new Error('The pilot proof does not match the existing Machine owner pin.');
    }
    const signature = Buffer.from(reply.signature, 'base64');
    if (signature.length > 72 || signature.toString('base64') !== reply.signature ||
        !verify('sha256', bytes, owner, signature) || challenge.expires_at <= Math.floor(Date.now() / 1000)) {
      throw new Error('Invalid or expired pilot owner proof.');
    }
    return JSON.stringify(reply);
  };
}

async function readPairingChallenge(input) {
  const parts = [];
  let length = 0;
  if (input.isTTY) throw new Error('Provide the Machine pairing challenge on standard input.');
  for await (const part of input) {
    length += part.length;
    if (length > 2048) throw new Error('Pairing challenge is too large.');
    parts.push(part);
  }
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
}

function readPinFile(path, limit, privateOwner) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = fstatSync(fd);
    if (!s.isFile() || s.size > limit || (privateOwner !== undefined &&
        (s.uid !== privateOwner || (s.mode & 0o7777) !== 0o600))) throw new Error('Invalid owner pin file.');
    const buffer = Buffer.alloc(limit + 1);
    let size = 0;
    while (size <= limit) {
      const n = readSync(fd, buffer, size, buffer.length - size, null);
      if (!n) break;
      size += n;
    }
    if (size > limit) throw new Error('Owner pin file is too large.');
    return buffer.toString('utf8', 0, size);
  } finally {
    closeSync(fd);
  }
}

export function existingMachinePin({ prefix = '/opt/homebrew', account = userInfo() } = {}) {
  // A daily user's same-named configuration directory is not prefix-owner state.
  const install = lstatSync(prefix);
  if (!install.isDirectory() || account.uid <= 0 || install.uid !== account.uid) {
    throw new Error('Use --owner-pin-file with the public key previously confirmed by the Machine administrator.');
  }
  const config = join(account.homedir, '.config');
  const state = join(config, 'agent-machine');
  for (const dir of [account.homedir, config, state]) {
    const s = lstatSync(dir);
    if (!s.isDirectory() || s.uid !== account.uid || (s.mode & 0o022) !== 0) throw new Error('Untrusted Machine state path.');
  }
  return JSON.parse(readPinFile(join(state, 'owner-pair.json'), 4096, account.uid)).owner;
}

export async function runPilot(args, { input = process.stdin, providerOptions, cliOptions } = {}) {
  const explicitPin = args[0] === '--owner-pin-file';
  const [operation, ...rest] = explicitPin ? args.slice(2) : args;
  if (!(operation === 'approve-pairing' && !rest.length || operation === 'review-first-hq' && rest.length === 1)) {
    throw new Error('Usage: node tools/private-pilot/machine-owner.mjs [--owner-pin-file FILE] approve-pairing | review-first-hq FILE');
  }
  const pin = explicitPin ? readPinFile(args[1], 256).trim() : existingMachinePin();
  const approve = pilotProvider(pin, providerOptions);
  return runMachineCli([operation, ...rest], {
    ...cliOptions,
    ownerPresence: async (command, options) => approve(command, await readPairingChallenge(input), options),
    firstHQReview: (file, options) => openFirstHQReview(file, { ...options,
      signer: (challenge, signerOptions) => approve('approve-first-hq', challenge, signerOptions) }),
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runPilot(process.argv.slice(2)).then(code => { process.exitCode = code; })
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
