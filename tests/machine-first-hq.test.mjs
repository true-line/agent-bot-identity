import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { firstHQSignedBytes, reviewFirstHQ, verifiedFirstHQProof } from '../machine-first-hq.mjs';
import { showFirstHQReview } from '../web/first-hq.js';
import { membersPlanCanonical } from '../machine-members.mjs';

const transfer = JSON.parse(readFileSync(new URL('./fixtures/first-hq-challenge.json', import.meta.url)));
const plan = JSON.parse(transfer.plan_canonical);

function withPlan(changed) {
  const text = typeof changed === 'string' ? changed : membersPlanCanonical(changed);
  return { ...transfer, plan_canonical: text, plan_digest: createHash('sha256').update(text).digest('hex') };
}

test('the Go first-HQ plan and exact signed bytes interoperate', () => {
  assert.deepEqual(reviewFirstHQ(transfer, 1000).plan, plan);
  assert.equal(firstHQSignedBytes(transfer).toString(),
    ['agent-bot-machine-owner/v1', 'first-hq-provision', 'ab'.repeat(32), 'plan-20261119T020000Z-abcd',
      '2d82ea20059ea1188eeab2ec889bcf4133779f346cfc3881c0663bfd483a710c', 'f0'.repeat(32), '1120', ''].join('\n'));
  const service = { kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create',
    owner: 'operator', content: '{"plist":"<key>Label</key>"}', detail: 'verify the approved release' };
  const changed = withPlan({ ...plan, steps: [...plan.steps, service] });
  assert.deepEqual(reviewFirstHQ(changed, 1000).plan.steps[1], service);
});

test('first-HQ review displays the complete planned runtime directory alongside the service', (t) => {
  function element(tag) {
    return { tag, children: [], append(...nodes) { this.children.push(...nodes); },
      replaceChildren(...nodes) { this.children = nodes; }, addEventListener() {} };
  }
  globalThis.document = { createElement: element };
  t.after(() => { delete globalThis.document; });

  const service = { kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create',
    owner: 'operator', detail: 'Install the reviewed service' };
  const record = { plist: '<plist/>', service: { release_dir: '/Library/Example/HQ' }, owner_uid: 501 };
  function displayedSteps(steps) {
    const box = element('section');
    showFirstHQReview(box, reviewFirstHQ(withPlan({ ...plan, steps }), 1000));
    return box.children.find(node => node.tag === 'ol').children;
  }
  function serviceFields(serviceRecord) {
    const steps = displayedSteps([plan.steps[0], { ...service, content: JSON.stringify(serviceRecord) }]);
    return steps[1].children.map(node => node.textContent);
  }

  assert.equal(displayedSteps(plan.steps).length, 1);
  const legacy = serviceFields(record);
  assert.ok(legacy.includes(record.plist));
  assert.ok(!legacy.includes('HQ runtime directory'));
  for (const action of ['create', 'none']) {
    const directory = { path: '/Library/Application Support/ai.true-line.agent-bot-hq',
      action, owner: 'root', group: 'wheel', mode: '0755' };
    const fields = serviceFields({ ...record, runtime_directory: directory });
    const index = fields.indexOf('HQ runtime directory');
    assert.ok(index >= 0, 'the service step must label the planned directory');
    assert.deepEqual(JSON.parse(fields[index + 1]), directory);
    assert.ok(fields.includes(record.plist));
  }
});

test('refuses altered, noncanonical, replayed and broader first-HQ inputs', () => {
  for (const bad of [
    { ...transfer, extra: true }, { ...transfer, action: 'machine-pair' }, { ...transfer, plan_digest: 'a'.repeat(64) },
    { ...transfer, nonce: transfer.nonce + '\n' }, { ...transfer, plan_id: transfer.plan_id + '\n' },
    { ...transfer, expires_at: 1000 }, { ...transfer, expires_at: 1121 }, { ...transfer, expires_at: true },
    withPlan(transfer.plan_canonical.replace('"version":3', '"version":3,"version":3')),
    withPlan(transfer.plan_canonical.trimEnd()), withPlan({ ...plan, members: ['_abm-member'] }),
    withPlan({ ...plan, members: null }), withPlan({ ...plan, steps: [] }),
    withPlan({ ...plan, steps: [{ ...plan.steps[0], action: 'repair' }] }),
    withPlan({ ...plan, steps: [{ ...plan.steps[0], target: 'another-account' }] }),
    withPlan({ ...plan, steps: [plan.steps[0], { kind: 'service', target: 'another-service', action: 'create' }] }),
  ]) assert.throws(() => reviewFirstHQ(bad, 1000));
  assert.throws(() => verifiedFirstHQProof(transfer, '{"public_key":"AA==","signature":"AA=="}'));
});

test('fresh first-HQ CLI review is local, single-use and ends on direct browser closure', async (t) => {
  const { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { openFirstHQReview } = await import('../machine-first-hq-review.mjs');
  const { runMachineCli } = await import('../cli/machine.mjs');
  const home = mkdtempSync(join(tmpdir(), 'first-hq-owner-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const file = join(home, 'transfer.json');
  const cfg = join(home, 'config.json');
  writeFileSync(file, JSON.stringify(transfer));
  writeFileSync(cfg, JSON.stringify({ settings: { keydTeamId: 'ABCDE12345' } }));
  const env = { HOME: home, AGENT_BOT_CONFIG: cfg };
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { x, y } = publicKey.export({ format: 'jwk' });
  const public_key = Buffer.concat([Buffer.of(4), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')]).toString('base64');
  let asks = 0;
  const signer = async (challenge) => {
    asks++;
    assert.deepEqual(challenge, transfer);
    return JSON.stringify({ public_key, signature: sign('sha256', firstHQSignedBytes(challenge), privateKey).toString('base64') });
  };
  for (const action of ['approve', 'discard', 'close', 'unavailable']) {
    let opened;
    const opening = new Promise((resolve) => { opened = resolve; });
    const stdout = [];
    const completed = runMachineCli(['review-first-hq', file], {
      env, home, stdout: { write: (s) => stdout.push(s) },
      // Only the browser launcher and physical signing are test substitutes.
      firstHQReview: (file, options) => openFirstHQReview(file, {
        ...options, platform: 'darwin', now: () => 1000, signer: action === 'unavailable' ? undefined : signer, openBrowser: (url) => opened(new URL(url)),
      }),
    });
    const unavailable = action === 'unavailable'
      ? assert.rejects(completed, { code: 'machine-owner-provider-unavailable' }) : null;
    const url = await opening;
    const origin = url.origin;
    const launch = url.hash.slice(1);
    const post = (verb, token, body, extra = {}) => fetch(origin + '/first-hq/' + verb, {
      method: 'POST', headers: { authorization: 'Bearer ' + token, origin, 'content-type': 'application/json', ...extra },
      body: JSON.stringify(body),
    });
    assert.match(await (await fetch(url)).text(), /First HQ provisioning/);
    assert.equal((await fetch(origin + '/ui/api/approvals')).status, 404);
    assert.equal((await post('claim', launch, {}, { origin: 'https://example.invalid' })).status, 403);
    assert.equal((await post('claim', launch, {}, { 'x-forwarded-for': '192.0.2.1' })).status, 403);
    assert.equal((await post('claim', 'wrong', {})).status, 403);
    const { session, review } = await (await post('claim', launch, {})).json();
    assert.deepEqual(review.plan, plan);
    assert.equal((await post('claim', launch, {})).status, 403);
    assert.equal((await post('approve', launch, { plan_digest: transfer.plan_digest })).status, 403);
    assert.equal((await post('approve', session, { plan_digest: '0'.repeat(64) })).status, 409);
    const result = await post(action === 'unavailable' ? 'approve' : action, session, action === 'close' ? {} : { plan_digest: transfer.plan_digest });
    assert.equal(result.status, action === 'unavailable' ? 503 : 200);
    if (action === 'unavailable') assert.deepEqual(await result.json(), { error: 'machine-owner-provider-unavailable' });
    if (action === 'approve') assert.equal(verifiedFirstHQProof(transfer, await result.text()).public_key, public_key);
    if (unavailable) await unavailable;
    else assert.equal(await completed, action === 'approve' ? 0 : 1);
    assert.ok(stdout.every((s) => !s.includes(launch) && !s.includes(session)));
    await assert.rejects(fetch(url));
  }
  assert.equal(asks, 1);
  assert.deepEqual(readdirSync(home).sort(), ['config.json', 'transfer.json']);
  assert.deepEqual(JSON.parse(readFileSync(file)), transfer);
});

test('closing the one-shot review revokes an outstanding signer before any proof response', async (t) => {
  const { mkdtempSync, rmSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { openFirstHQReview } = await import('../machine-first-hq-review.mjs');
  const home = mkdtempSync(join(tmpdir(), 'first-hq-cancel-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const file = join(home, 'transfer.json');
  writeFileSync(file, JSON.stringify(transfer));
  let show, prompting;
  const page = new Promise((resolve) => { show = resolve; });
  const prompt = new Promise((resolve) => { prompting = resolve; });
  const done = openFirstHQReview(file, {
    home, platform: 'darwin', now: () => 1000,
    openBrowser: (url) => show(new URL(url)),
    signer: async (_, { signal }) => {
      prompting();
      await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      throw new Error('canceled');
    },
  });
  const url = await page;
  const post = (verb, token, body) => fetch(new URL(verb, url), {
    method: 'POST', headers: { authorization: 'Bearer ' + token, origin: url.origin, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const { session } = await (await post('claim', url.hash.slice(1), {})).json();
  const approved = post('approve', session, { plan_digest: transfer.plan_digest }).then((res) => res.status, () => 0);
  await prompt;
  const replay = await post('approve', session, { plan_digest: transfer.plan_digest });
  assert.equal(replay.status, 409);
  assert.equal((await post('close', session, {})).status, 200);
  assert.equal(await done, 'discarded');
  assert.notEqual(await approved, 200);
});
