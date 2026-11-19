// A transferred Machine challenge is public, untrusted data. Rebuild the plan
// with the same canonical encoder used by the saved-plan Approvals flow.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { membersPlanCanonical, membersPlanDigest, MEMBERS_PLAN_ID } from './machine-members.mjs';

const HQ = '_agent-bot-hq';
const fields = ['action', 'machine_key', 'plan_id', 'plan_digest', 'nonce', 'expires_at', 'plan_canonical'];
const hex = (s) => typeof s === 'string' && s.length === 64 && /^[0-9a-f]+$/.test(s);
const fieldsAre = (object, names) => object && typeof object === 'object' && !Array.isArray(object)
  && Object.keys(object).length === names.length && names.every((key) => Object.hasOwn(object, key));

export function reviewFirstHQ(challenge, now = Math.floor(Date.now() / 1000)) {
  if (!fieldsAre(challenge, fields) || challenge.action !== 'first-hq-provision'
    || ![challenge.machine_key, challenge.plan_digest, challenge.nonce].every(hex)
    || typeof challenge.plan_id !== 'string' || challenge.plan_id.length !== 26 || !MEMBERS_PLAN_ID.test(challenge.plan_id)
    || typeof challenge.plan_canonical !== 'string' || Buffer.byteLength(challenge.plan_canonical) > 48 * 1024) {
    throw new Error('Invalid first-HQ challenge.');
  }
  if (!Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= now || challenge.expires_at > now + 120) {
    throw new Error('The first-HQ challenge expired or has an invalid expiry.');
  }
  const plan = JSON.parse(challenge.plan_canonical);
  if (membersPlanCanonical(plan) !== challenge.plan_canonical || membersPlanDigest(plan) !== challenge.plan_digest) {
    throw new Error('The transferred plan differs from its canonical bytes or digest.');
  }
  const [account, service] = plan.steps;
  if (plan.version !== 3 || plan.hq_account !== HQ || plan.dir !== 'none' || !Array.isArray(plan.members) || plan.members.length
    || plan.steps.length < 1 || plan.steps.length > 2
    || !fieldsAre(account, ['kind', 'target', 'action', 'group', 'mode', 'detail'])
    || account.kind !== 'hq-account' || account.target !== HQ || account.group !== HQ || account.mode !== '0700'
    || account.action !== 'create' || !account.detail
    || (service && (!fieldsAre(service, ['kind', 'target', 'action', 'owner', 'content', 'detail'])
      || service.kind !== 'service' || service.target !== 'ai.true-line.agent-bot-hq'
      || !['create', 'write'].includes(service.action) || !service.owner || !service.content || !service.detail))) {
    throw new Error('This plan is outside first-HQ provisioning.');
  }
  const fingerprint = createHash('sha256').update(Buffer.from(challenge.machine_key, 'hex')).digest('hex');
  return { plan, machine_fingerprint: fingerprint, plan_id: challenge.plan_id, plan_digest: challenge.plan_digest, expires_at: challenge.expires_at };
}

export function firstHQSignedBytes(challenge) {
  return Buffer.from(['agent-bot-machine-owner/v1', 'first-hq-provision', challenge.machine_key,
    challenge.plan_id, challenge.plan_digest, challenge.nonce, challenge.expires_at, ''].join('\n'), 'utf8');
}

export function verifiedFirstHQProof(challenge, output) {
  return verifyMachineOwnerProof(firstHQSignedBytes(challenge), output);
}

export function verifyMachineOwnerProof(bytes, output, expectedKey) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > 1024) throw new Error('Invalid owner proof.');
  const proof = JSON.parse(output);
  if ((expectedKey !== undefined && proof?.public_key !== expectedKey) || !fieldsAre(proof, ['public_key', 'signature']) || typeof proof.public_key !== 'string' || typeof proof.signature !== 'string') {
    throw new Error('Invalid owner proof.');
  }
  const point = Buffer.from(proof.public_key, 'base64');
  const signature = Buffer.from(proof.signature, 'base64');
  if (point.length !== 65 || point[0] !== 4 || point.toString('base64') !== proof.public_key
    || signature.length > 72 || signature.toString('base64') !== proof.signature) throw new Error('Invalid owner proof.');
  const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
  if (!verify('sha256', bytes, key, signature)) throw new Error('Invalid owner proof.');
  return proof;
}
