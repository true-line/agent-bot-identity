// Real public SDK and Unix sockets with protocol endpoints, not a release,
// installed-harness, production authority or complete shared-corpus proof.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import { connectMemberQueries } from '../identity/vendor/agent-bot-sdk/member-client.mjs';
import { canonicalBytes } from '../identity/vendor/agent-bot-sdk/wire/canonical-json.mjs';
import { createHqInboxClient } from '../identity/hq-inbox-client.mjs';

const SOUL = 'agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b';
async function endpoints({ lose = false } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'hq-sdk-')); const entryPath = join(home, 'm.sock'); const brokerPath = join(home, 'b.sock');
  const sockets = new Set(); const calls = []; let consumed = false;
  const channel = 'BINDING_CANARY_0123456789abcdef'; const nonce = 'a'.repeat(64); const token = 'TOKEN_CANARY';
  const serve = async (path, handler) => {
    const server = createServer((socket) => {
      sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
      const lines = createInterface({ input: socket });
      lines.on('line', (line) => {
        const request = JSON.parse(line); calls.push(request.op);
        const result = handler(request, socket);
        if (result !== undefined) socket.write(`${JSON.stringify({ id: request.id, ok: true, result })}\n`);
      });
    });
    await new Promise((r) => server.listen(path, r)); return server;
  };
  const entry = await serve(entryPath, (r) => {
    if (r.op === 'hello') { assert.equal(r.payload.token, token); return { soul_id: SOUL, member_id: 'member:one', role: 'lead' }; }
    assert.equal(r.op, 'runtime');
    return { runtime_id: 'runtime:one', channel_binding: channel, installation_epoch: 7, lease_generation: 12, broker: brokerPath };
  });
  const broker = await serve(brokerPath, (r, socket) => {
    if (r.op === 'bind.challenge') return { runtime_id: r.payload.runtime_id, nonce, algorithm: 'hmac-sha256', context: 'agent-bot-hq/bind/v1' };
    if (r.op === 'bind') {
      assert.equal(r.payload.proof, createHmac('sha256', channel).update(`agent-bot-hq/bind/v1\n${nonce}\nruntime:one`).digest('hex'));
      assert.equal(Object.hasOwn(r.payload, 'channel_binding'), false); return { runtime_id: 'runtime:one' };
    }
    assert.equal(r.op, 'notices.consume-one'); assert.equal(r.payload.installation_epoch, 7); assert.equal(r.payload.lease_generation, 12);
    const notices = consumed ? [] : [{ message_id: 'notice:one', provenance: ['external-untrusted'], wake_class: 'none', content: { repo: 'example/project', text: 'External data' } }];
    consumed = true;
    if (lose) { socket.destroy(); return; }
    return { contract: 'hq/v1', request_id: r.payload.request_id, operation: r.payload.operation, required_capabilities: ['notices-v1'], notices };
  });
  return { entryPath, token, calls, consumed: () => consumed,
    async close() { for (const s of sockets) s.destroy(); await Promise.all([new Promise((r) => entry.close(r)), new Promise((r) => broker.close(r))]); rmSync(home, { recursive: true, force: true }); } };
}

for (const lose of [false, true]) test(`public SDK authenticates real sockets and ${lose ? 'never replays an unknown consume outcome' : 'hands off one then empty'}`, async () => {
  const t = await endpoints({ lose }); let member;
  try {
    // The protocol fixture intentionally carries no shared authority record.
    // Unexpected use of the required validation adapter refuses, never passes.
    member = await connectMemberQueries({ memberSocket: t.entryPath, memberToken: t.token, contracts: {
      record() { throw new Error('unexpected shared record in protocol fixture'); }, admission() { throw new Error('unexpected admission in protocol fixture'); },
    } });
    const client = createHqInboxClient({ queries: member.queries, validateQuery: () => [], validateResult: () => [], canonicalBytes, requestId: () => 'query:network' });
    if (lose) {
      await assert.rejects(client.takeInbox());
      assert.equal(t.consumed(), true); assert.equal(t.calls.filter((op) => op === 'notices.consume-one').length, 1);
      assert.equal(t.calls.filter((op) => op === 'runtime').length, 1); assert.equal(t.calls.filter((op) => op === 'bind').length, 1);
    } else {
      assert.deepEqual(await client.takeInbox(), { event: { id: 'notice:one', repo: 'example/project', text: 'External data', pulled: true } });
      assert.deepEqual(await client.takeInbox(), { event: null });
      assert.equal(t.calls.filter((op) => op === 'notices.consume-one').length, 2);
    }
  } finally { await member?.close(); await t.close(); }
});
