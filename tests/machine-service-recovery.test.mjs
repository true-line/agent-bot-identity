import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { membersPlanCanonical } from '../machine-members.mjs';
import { responseCanonical } from '../machine-client.mjs';
import { recoverySignedBytes, reviewHQServiceRecovery, verifyRecoveryEnvelope } from '../machine-service-recovery.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const machine = generateKeyPairSync('ed25519');
const publicRaw = machine.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const fingerprint = sha(publicRaw);
const owner = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const { x, y } = owner.publicKey.export({ format: 'jwk' });
const ownerKey = Buffer.concat([Buffer.from([4]), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')]).toString('base64');
const now = Date.now();
const instant = Math.floor(now / 1000);
function challenge() {
  const hq = '_agent-bot-hq';
  const canonical = membersPlanCanonical({ version: 3, hq_account: hq, dir: 'none', members: [], steps: [
    { kind: 'hq-account', target: hq, action: 'none', group: hq, mode: '0700', detail: 'verified private home' },
    { kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create', owner: 'operator', content: JSON.stringify({ service: { release_dir: '/Library/Example/HQ', artifact_sha256: 'cd'.repeat(32), node: '/Library/Example/node', node_sha256: 'de'.repeat(32), archive: '/Library/Example/approved.tar' }, plist: '<plist>\n<dict/>\n</plist>', owner_uid: 501 }), detail: 'verified service' },
  ] });
  return { action: 'hq-service-recovery', machine_key: publicRaw.toString('hex'), hq_key: 'aa'.repeat(32),
    owner_key: ownerKey, plan_id: 'plan-20261119T000000Z-ab12', plan_digest: sha(canonical), nonce: 'bb'.repeat(32), expires_at: instant + 120, plan_canonical: canonical };
}
function envelope(body) {
  const f = { ok: true, state: 'challenged', body, timestamp: instant, nonce: 'reply', request_nonce: 'request' };
  f.signature = sign(null, responseCanonical(f, Buffer.from(JSON.stringify(body))), machine.privateKey).toString('base64');
  return JSON.stringify(f) + '\n';
}
test('recovery review binds the original signed response, trusted Machine and current service plan', () => {
  const c = challenge();
  const line = envelope(c);
  assert.equal(verifyRecoveryEnvelope(line, fingerprint, now).plan.steps[1].owner, 'operator');
  assert.throws(() => verifyRecoveryEnvelope(line, '00'.repeat(32), now), /identity/);
  assert.throws(() => verifyRecoveryEnvelope(line, fingerprint, (instant + 120) * 1000), /expired/);
  assert.throws(() => verifyRecoveryEnvelope(line.replace('verified service', 'modified service'), fingerprint, now), /signature/);
  assert.throws(() => verifyRecoveryEnvelope(line.replace('"body":', '"body":{},"body":'), fingerprint, now));
  for (const [before, after] of [['"action":"none"', '"action":"create"'], ['"members":[]','"members":null']]) {
    const canonical = c.plan_canonical.replace(before, after);
    assert.throws(() => verifyRecoveryEnvelope(envelope({ ...c, plan_digest: sha(canonical), plan_canonical: canonical }), fingerprint, now), /outside recovery/);
  }
  assert.throws(() => verifyRecoveryEnvelope(envelope({ ...c, action: 'first-hq-provision' }), fingerprint, now));
});
test('recovery review checks the exact HQ runtime directory operation', () => {
  const dir = { path: '/Library/Application Support/ai.true-line.agent-bot-hq', action: 'create', owner: 'root', group: 'wheel', mode: '0755' };
  function review(runtimeDirectory, serviceAction = 'create') {
    const c = challenge();
    const plan = JSON.parse(c.plan_canonical);
    const step = plan.steps[1];
    step.action = serviceAction;
    step.content = JSON.stringify({ ...JSON.parse(step.content), runtime_directory: runtimeDirectory });
    c.plan_canonical = membersPlanCanonical(plan);
    c.plan_digest = sha(c.plan_canonical);
    return verifyRecoveryEnvelope(envelope(c), fingerprint, now).record.runtime_directory;
  }
  assert.deepEqual(review(dir), dir);
  const existing = { ...dir, action: 'none' };
  for (const action of ['create', 'write']) assert.deepEqual(review(existing, action), existing);
  assert.throws(() => review(dir, 'write'), /Invalid HQ runtime directory/);
  for (const invalid of [null, { ...dir, path: '/Library' }, { ...dir, action: 'delete' },
    { ...dir, owner: 'operator' }, { ...dir, group: 'staff' }, { ...dir, mode: '0777' }, { ...dir, extra: 'field' }]) {
    assert.throws(() => review(invalid), /Invalid HQ runtime directory/);
  }
});

test('local terminal displays full plan and obtains a purpose-bound proof only after confirmation', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'hq-service-review-'));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const file = join(tmp, 'challenge.json');
  const c = challenge();
  writeFileSync(file, envelope(c));
  for (const answer of ['', 'approve']) {
    const input = new PassThrough();
    input.isTTY = true;
    let text = '';
    let answered = false;
    const display = new Writable({ write(chunk, encoding, done) {
      text += chunk.toString();
      if (!answered && text.includes('Type approve')) { answered = true; setImmediate(() => input.write(answer + '\n')); }
      done();
    } });
    display.isTTY = true;
    let called = false;
    const proof = await reviewHQServiceRecovery(file, fingerprint, { platform: 'darwin', input, display, now: () => now,
      sign: async (signed) => {
        called = true;
        assert.ok(text.includes('verified service') && text.includes('operator') && text.includes('<plist>\n<dict/>\n</plist>'));
        assert.deepEqual(signed, c);
        return JSON.stringify({ public_key: ownerKey, signature: sign('sha256', recoverySignedBytes(signed), owner.privateKey).toString('base64') });
      },
    });
    assert.equal(called, answer === 'approve');
    assert.equal(proof?.public_key ?? null, answer ? ownerKey : null);
    input.destroy(); display.destroy();
  }
});
