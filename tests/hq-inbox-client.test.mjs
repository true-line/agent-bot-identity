import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHqInboxClient } from '../identity/hq-inbox-client.mjs';

const notice = () => ({ message_id: 'review:client-prep', provenance: ['external-untrusted'], wake_class: 'notify',
  content: { repo: 'sample/notice-client', event: 'pull_request_review', action: 'submitted', title: 'Review received',
    text: 'External review text', number: 17, createdAt: 1_800_000_000_001, type: ['pr', 'review'] } });
const reply = (query, notices = [notice()]) => ({ contract: 'hq/v1', request_id: query.request_id,
  operation: 'consume-one', required_capabilities: ['notices-v1'], notices });

// These doubles exercise the client adapter. The installed MCP gate in
// tests/integration/hq-inbox-release-gate.test.mjs uses the reviewed HQ SDK
// and verifies the genuine pinned soul-contracts v0.5.0 schemas.
function fixture(overrides = {}) {
  const calls = [];
  const options = {
    request: async (kind, query) => { calls.push({ kind, query }); return reply(query); },
    currentRuntime: () => ({ installation_epoch: 7, lease_generation: 12 }),
    validateQuery: () => [], validateResult: () => [],
    canonicalBytes: (value) => Buffer.from(JSON.stringify(value)),
    requestId: () => 'client:request-17',
    ...overrides,
  };
  const queries = Object.hasOwn(overrides, 'queries') ? overrides.queries : {
    async request(kind, build, policy) {
      assert.deepEqual(policy, { replay: 'never' });
      const query = build(options.currentRuntime());
      assert.equal(typeof query?.then, 'undefined');
      return options.request(kind, query);
    },
  };
  return { client: createHqInboxClient({ ...options, queries }), calls, options };
}

test('fixed-one query uses only bound freshness and preserves the sanitized legacy envelope', async () => {
  const f = fixture({ validateQuery: (query) => {
    assert.ok(Object.isFrozen(query)); assert.ok(Object.isFrozen(query.required_capabilities)); return [];
  } });
  const out = await f.client.takeInbox();
  assert.deepEqual(f.calls, [{ kind: 'notices.consume-one', query: { contract: 'hq/v1', request_id: 'client:request-17',
    operation: 'consume-one', required_capabilities: ['notices-v1'], installation_epoch: 7, lease_generation: 12 } }]);
  assert.deepEqual(out, { event: { id: notice().message_id, ...notice().content, pulled: true } });
  assert.equal(Object.hasOwn(out.event, 'provenance'), false);
  assert.equal(Object.hasOwn(out.event, 'wake_class'), false);
  const empty = fixture({ request: async (_, query) => reply(query, []) });
  assert.deepEqual(await empty.client.takeInbox(), { event: null });
});

test('no caller selectors, absent freshness or non-validation verdict can send a broker request', async () => {
  for (const input of [{ harness: 'other' }, { repo: 'other/repo' }, { runtime_id: 'other' }, { count: 2 }, {}]) {
    const f = fixture();
    await assert.rejects(f.client.takeInbox(input), { code: 'inbox-bad-request' });
    assert.equal(f.calls.length, 0);
  }
  for (const runtime of [null, {}, { installation_epoch: 7, lease_generation: 0 },
    { installation_epoch: 7.5, lease_generation: 12 }, { installation_epoch: 7, lease_generation: 12, runtime_id: 'selector' }]) {
    const f = fixture({ currentRuntime: () => runtime });
    await assert.rejects(f.client.takeInbox(), { code: 'inbox-no-live-runtime' });
    assert.equal(f.calls.length, 0);
  }
  for (const verdict of [true, false, undefined, [{ keyword: 'required' }]]) {
    const f = fixture({ validateQuery: () => verdict });
    await assert.rejects(f.client.takeInbox(), { code: 'inbox-bad-request' });
    assert.equal(f.calls.length, 0);
  }
});

test('all integration dependencies are mandatory; no permissive transport or validator default', () => {
  for (const dependency of ['queries', 'validateQuery', 'validateResult', 'canonicalBytes']) {
    assert.throws(() => fixture({ [dependency]: undefined }), TypeError);
  }
});

test('refusal or lost reply propagates without replay, reconnect or remote fallback', async () => {
  for (const code of ['caller_mismatch', 'stale_epoch', 'lease_expired', 'host.unknown_kind', 'transport']) {
    let sends = 0, fresh = 0;
    const error = Object.assign(new Error('refused or unknown outcome'), { code, transport: code === 'transport' });
    const f = fixture({ currentRuntime: () => { fresh++; return { installation_epoch: 7, lease_generation: 12 }; },
      request: () => { sends++; throw error; } });
    await assert.rejects(f.client.takeInbox(), (e) => e === error);
    assert.equal(sends, 1); assert.equal(fresh, 1);
  }
});

test('freshness is read for each call, and no client-side queue or authority is retained', async () => {
  let generation = 12;
  const f = fixture({ currentRuntime: () => ({ installation_epoch: 7, lease_generation: generation++ }) });
  await f.client.takeInbox(); await f.client.takeInbox();
  assert.deepEqual(f.calls.map(({ query }) => query.lease_generation), [12, 13]);
});

test('response version, capability, correlation, operation and failed validation refuse acceptance', async () => {
  for (const [mutate, code] of [
    [(value) => { value.contract = 'hq/v9'; }, 'unsupported_version'],
    [(value) => { value.required_capabilities = []; }, 'required_capability_missing'],
    [(value) => { value.required_capabilities.push('unknown-v1'); }, 'required_capability_missing'],
    [(value) => { value.request_id = 'wrong'; }, 'inbox-invalid-response'],
    [(value) => { value.operation = 'peek'; }, 'inbox-invalid-response'],
    [(value) => { value.notices.push(notice()); }, 'inbox-invalid-response'],
  ]) {
    const f = fixture({ request: (_, query) => { const value = reply(query); mutate(value); return value; } });
    await assert.rejects(f.client.takeInbox(), { code });
  }
  for (const verdict of [true, undefined, [{ keyword: 'additionalProperties' }]]) {
    const f = fixture({ validateResult: () => verdict });
    await assert.rejects(f.client.takeInbox(), { code: 'inbox-invalid-response' });
  }
});

test('legacy projection cannot expose transport or custody fields even in a faulty validated response', async () => {
  const f = fixture({ request: (_, query) => {
    const value = reply(query);
    Object.assign(value.notices[0].content, { id: 'forged', lease: 'secret-lease', attempts: 9, credential: 'secret', pulled: false });
    return value;
  } });
  assert.deepEqual(await f.client.takeInbox(), { event: { id: notice().message_id, ...notice().content, pulled: true } });
});

test('canonical source byte budget is inclusive and measured in UTF-8 bytes', async () => {
  const source = { id: notice().message_id, ...notice().content, text: '' };
  const remaining = 65_536 - Buffer.byteLength(JSON.stringify(source));
  for (const [text, accepted] of [['x'.repeat(remaining), true], ['x'.repeat(remaining + 1), false], ['λ'.repeat(remaining), false]]) {
    const f = fixture({ request: (_, query) => { const n = notice(); n.content.text = text; return reply(query, [n]); } });
    if (accepted) assert.equal((await f.client.takeInbox()).event.text, text);
    else await assert.rejects(f.client.takeInbox(), { code: 'frame_too_large' });
  }
});

test('full result budget and canonicalizer failures are checked before mapping', async () => {
  for (const canonicalBytes of [
    (value) => Buffer.alloc(value.contract ? 524_289 : 1),
    () => { throw new TypeError('lone surrogate or non-JSON'); },
    () => 'not bytes',
  ]) {
    const f = fixture({ canonicalBytes });
    await assert.rejects(f.client.takeInbox(), (e) => ['frame_too_large', 'inbox-invalid-response'].includes(e.code));
  }
});

test('validation builders are synchronous and refuse thenables before a transport send', async () => {
  for (const validateQuery of [() => Promise.resolve([]), async () => { throw new Error('async validation'); }]) {
    const f = fixture({ validateQuery });
    await assert.rejects(f.client.takeInbox(), { code: 'inbox-bad-request' }); assert.equal(f.calls.length, 0);
  }
  const f = fixture({ validateResult: () => Promise.resolve([]) });
  await assert.rejects(f.client.takeInbox(), { code: 'inbox-invalid-response' }); assert.equal(f.calls.length, 1);
});

test('a query port cannot return an uncorrelated result without building its request', async () => {
  const f = fixture({ queries: { request: () => reply({ request_id: 'unbuilt' }) } });
  await assert.rejects(f.client.takeInbox(), { code: 'inbox-invalid-response' });
});
