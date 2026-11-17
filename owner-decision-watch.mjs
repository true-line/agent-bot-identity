// Owner-decision watch identity (agent-comms#77, slice C0): disabled and pure.
// Matches the broker's watch binding at agent-comms a6e9901 (merged #210).
// The broker's account-watch `ready` event carries a broker-generated
// `watchId`, the pairing's current `daemonEpoch` and `daemonKey`. For a v1
// pairing that is SHA-256 of the exact daemon vouch SPKI DER presented at
// pairing. For a v2 pairing it is the domain-separated digest defined by
// agent-comms ADR-0309. The comms supervisor
// records that identity once per socket; owner-decision relay events are
// accepted only when they carry exactly the identity of the socket they
// arrived on. Nothing here dispatches an owner decision, persists the
// identity, or treats it as authority: it is in-memory socket binding only,
// and a reconnect starts over with no replay.
import { createHash, createPublicKey } from 'node:crypto';

export const OWNER_DECISION_EVENTS = Object.freeze(['owner-decision-prepare', 'owner-decision', 'owner-decision-cancel']);
export const DAEMON_IDENTITY_V2_LABEL = 'agent-comms/daemon-identity/v2';
const UUID4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const DEVICE = /^[A-Za-z0-9._:-]{1,128}$/;
const matches = (pattern, value) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// The daemonKey we expect: SHA-256 of our own vouch public key's SPKI DER
// bytes (44 for Ed25519), never of the PEM text.
// Computed locally, so the broker's value is checked, never trusted.
export function daemonKeyFromPublicKeyPem(publicKeyPem) {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ed25519' || der.length !== 44) {
    throw Object.assign(new Error('the daemon vouch key is not an Ed25519 public key'), { code: 'owner-watch-identity' });
  }
  return sha256(der);
}

// The v2 daemon identity is the broker's ADR-0309 derivation over the exact
// normalized descriptor that pair-comms pinned. It is an identifier, not a
// public key, and is never accepted from the broker as its own proof.
export function daemonKeyFromSoulTokens(descriptor) {
  const { v, issuer, device } = descriptor ?? {};
  let parsed;
  try { parsed = new URL(issuer); } catch { parsed = null; }
  if (v !== 2 || !parsed || parsed.protocol !== 'https:' || parsed.origin !== issuer
    || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash
    || !matches(DEVICE, device)) {
    throw Object.assign(new Error('the soul-token v2 daemon identity descriptor is invalid'), { code: 'owner-watch-identity' });
  }
  return sha256(Buffer.from(`${DAEMON_IDENTITY_V2_LABEL}\n${issuer}\n${device}`, 'utf8'));
}

// The identity a `ready` event binds. Two cases bind nothing, silently, and
// keep wake and launch working: an old broker's bare `ready` (none of the
// three fields), and a daemon with no expected daemonKey configured (owner
// intake is off). Anything else that cannot bind (partial or malformed fields,
// or a daemonKey that is not ours) also binds nothing, but throws a
// diagnosable `owner-watch-identity` error for the caller to surface; it is
// never a silent no-op.
export function watchIdentityFromReady(event, { daemonKey = null } = {}) {
  if (event === null || typeof event !== 'object' || daemonKey === null) return null;
  const fields = ['watchId', 'daemonEpoch', 'daemonKey'].filter((key) => Object.hasOwn(event, key));
  if (fields.length === 0) return null;
  const refuse = (detail) => { throw Object.assign(new Error(`owner-decision watch identity not bound: ${detail}`), { code: 'owner-watch-identity' }); };
  if (!matches(DIGEST, daemonKey)) refuse('the expected daemonKey is malformed');
  const { watchId, daemonEpoch } = event;
  if (fields.length !== 3 || !matches(UUID4, watchId) || !Number.isSafeInteger(daemonEpoch) || daemonEpoch < 1
    || !matches(DIGEST, event.daemonKey)) refuse('the ready event identity is malformed');
  if (event.daemonKey !== daemonKey) refuse('the broker daemonKey does not match this daemon\'s paired identity');
  return Object.freeze({ watchId, daemonEpoch, daemonKey });
}

// Whether one relay event may be taken in on the socket whose identity is
// `identity`: an owner-decision event whose three bindings equal it exactly.
export function ownerDecisionIntakeBound(event, identity) {
  return identity !== null && typeof identity === 'object' && event !== null && typeof event === 'object'
    && OWNER_DECISION_EVENTS.includes(event.event)
    && event.watchId === identity.watchId && event.daemonEpoch === identity.daemonEpoch && event.daemonKey === identity.daemonKey;
}
