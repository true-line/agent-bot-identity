import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { approveHQServiceRecovery, parseMachineHandoffJSON } from './identity-host.mjs';
import { readMachineChallengeText } from './machine-challenge-file.mjs';
import { verifyResponse } from './machine-client.mjs';
import { verifyMachineOwnerProof } from './machine-first-hq.mjs';
import { membersPlanCanonical, MEMBERS_PLAN_ID } from './machine-members.mjs';

const purpose = 'hq-service-recovery';
const hex = (s) => typeof s === 'string' && s.length === 64 && /^[0-9a-f]+$/.test(s);
const fingerprint = (bytes) => createHash('sha256').update(bytes).digest('hex');
const keysAre = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const frameFields = ['ok', 'state', 'body', 'timestamp', 'nonce', 'request_nonce', 'signature'];
const challengeFields = ['action', 'machine_key', 'hq_key', 'owner_key', 'plan_id', 'plan_digest', 'nonce', 'expires_at', 'plan_canonical'];
const compact = (s) => typeof s === 'string' && s.length <= 128 && /^[A-Za-z0-9_-]+$/.test(s);

export function verifyRecoveryEnvelope(line, trustedFingerprint, now = Date.now()) {
  if (!hex(trustedFingerprint) || typeof line !== 'string' || Buffer.byteLength(line.replace(/\n$/, '')) > 65536 || /[\r\n]/.test(line.replace(/\n$/, ''))) {
    throw new Error('Expected one signed Machine response and an independently verified Machine SHA-256 fingerprint.');
  }
  const frame = parseMachineHandoffJSON(line);
  const c = frame?.body;
  if (!keysAre(frame, frameFields) || frame.ok !== true || frame.state !== 'challenged' || !Number.isSafeInteger(frame.timestamp)
    || !compact(frame.nonce) || !compact(frame.request_nonce) || !keysAre(c, challengeFields)
    || c.action !== purpose || ![c.machine_key, c.hq_key, c.plan_digest, c.nonce].every(hex) || c.machine_key === c.hq_key
    || typeof c.owner_key !== 'string' || typeof c.plan_id !== 'string' || c.plan_id.length !== 26 || !MEMBERS_PLAN_ID.test(c.plan_id)
    || typeof c.plan_canonical !== 'string' || !Number.isSafeInteger(c.expires_at)) throw new Error('Invalid HQ service recovery challenge.');
  const signature = typeof frame.signature === 'string' ? Buffer.from(frame.signature, 'base64') : null;
  if (signature?.length !== 64 || signature.toString('base64') !== frame.signature) throw new Error('Invalid Machine signature encoding.');
  const machine = Buffer.from(c.machine_key, 'hex');
  const owner = Buffer.from(c.owner_key, 'base64');
  if (fingerprint(machine) !== trustedFingerprint || owner.length !== 65 || owner[0] !== 4 || owner.toString('base64') !== c.owner_key) {
    throw new Error('Unexpected Machine identity or owner pin.');
  }
  verifyResponse(line, machine, { expectedNonce: frame.request_nonce, now });
  if (c.expires_at <= Math.floor(now / 1000) || c.expires_at > Math.floor(now / 1000) + 120
    || c.expires_at > frame.timestamp + 120 || c.expires_at <= frame.timestamp) throw new Error('HQ service recovery challenge has expired or has an invalid lifetime.');
  const plan = parseMachineHandoffJSON(c.plan_canonical);
  if (membersPlanCanonical(plan) !== c.plan_canonical || fingerprint(c.plan_canonical) !== c.plan_digest) throw new Error('Transferred plan digest mismatch.');
  const [account, service] = plan.steps;
  if (plan.version !== 3 || plan.hq_account !== '_agent-bot-hq' || plan.dir !== 'none' ||
    (!Array.isArray(plan.members) || plan.members.length !== 0) || plan.steps.length !== 2 ||
    !keysAre(account, ['kind', 'target', 'action', 'group', 'mode', 'detail']) || account.kind !== 'hq-account' ||
    account.target !== plan.hq_account || account.group !== plan.hq_account || account.mode !== '0700' || account.action !== 'none' ||
    !keysAre(service, ['kind', 'target', 'action', 'owner', 'content', 'detail']) || service.kind !== 'service' ||
    service.target !== 'ai.true-line.agent-bot-hq' || !['create', 'write'].includes(service.action) || !service.owner || !service.content) {
    throw new Error('This plan is outside recovery of the enrolled HQ service.');
  }
  const record = parseMachineHandoffJSON(service.content);
  if (!keysAre(record, ['service', 'plist', 'owner_uid']) || !Number.isSafeInteger(record.owner_uid) || record.owner_uid < 1 ||
    !keysAre(record.service, ['release_dir', 'artifact_sha256', 'node', 'node_sha256', 'archive']) ||
    ![record.service.artifact_sha256, record.service.node_sha256].every(hex) ||
    ![record.service.release_dir, record.service.node, record.service.archive].every((s) => typeof s === 'string' && s.startsWith('/')) ||
    typeof record.plist !== 'string' || !record.plist.length || /[^\x20-\x7e\t\n]/.test(record.plist)) {
    throw new Error('Invalid service release or LaunchDaemon configuration.');
  }
  return { challenge: c, plan, record, machineFingerprint: trustedFingerprint, hqFingerprint: fingerprint(Buffer.from(c.hq_key, 'hex')) };
}

export function recoverySignedBytes(c) {
  return Buffer.from(['agent-bot-machine-owner/v1', purpose, c.machine_key, c.hq_key, c.owner_key, c.plan_id, c.plan_digest, c.nonce, c.expires_at, ''].join('\n'));
}

export async function reviewHQServiceRecovery(file, trustedFingerprint, {
  env, home, platform = process.platform, input = process.stdin, display = process.stderr, now = Date.now, sign = approveHQServiceRecovery,
} = {}) {
  if (platform !== 'darwin' || !input.isTTY || !display.isTTY) throw new Error('Review the service plan in the local owner’s macOS Terminal.');
  const line = readMachineChallengeText(file, 65537);
  const { challenge, plan, record, machineFingerprint, hqFingerprint } = verifyRecoveryEnvelope(line, trustedFingerprint, now());
  const service = plan.steps[1];
  // Expand the service record once, so the owner can read the actual plist
  // lines. Preserve the unmodified canonical string for all verification.
  const { content, ...serviceStep } = service;
  const { plist, ...configuration } = record;
  const displayPlan = { ...plan, steps: [plan.steps[0], { ...serviceStep, content: configuration }] };
  display.write('Repair the paired HQ service\nMachine SHA-256 ' + machineFingerprint + '\nHQ SHA-256 ' + hqFingerprint +
    '\nPlan ' + challenge.plan_id + '\nPlan SHA-256 ' + challenge.plan_digest + '\nService owner ' + JSON.stringify(service.owner) +
    '\nExpires ' + new Date(challenge.expires_at * 1000).toISOString() + '\n' + JSON.stringify(displayPlan, null, 2) + '\nLaunchDaemon plist\n' + plist + '\n');
  const prompt = createInterface({ input, output: display, terminal: true });
  const signal = AbortSignal.timeout(Math.max(1, challenge.expires_at * 1000 - now()));
  let answer;
  try { answer = await prompt.question('Type approve to request owner presence, or press Return to discard: ', { signal }); }
  finally { prompt.close(); }
  if (answer !== 'approve') return null;
  verifyRecoveryEnvelope(line, trustedFingerprint, now());
  const output = await sign(challenge, { env, home, platform, signal });
  verifyRecoveryEnvelope(line, trustedFingerprint, now());
  return verifyMachineOwnerProof(recoverySignedBytes(challenge), output, challenge.owner_key);
}
