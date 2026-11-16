// Component composition: real SDK bootstrap and real socket + MCP EOF. The
// published dependency gate remains intact; this is not installed acceptance.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createInterface } from 'node:readline';
import { getEventListeners } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pinnedComponent } from './helpers/pinned-hq-components.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMcpState, runMcpServer } from '../agent-mcp.mjs';
import { connectMemberQueries } from '../identity/vendor/agent-bot-sdk/member-client.mjs';

const within = async (promise, message, timeout = 1500) => {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeout); })]); }
  finally { clearTimeout(timer); }
};

test('MCP EOF aborts a silent initial member hello before any SDK facade is returned', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-hello-')); const path = join(dir, 'member.sock'); const sockets = new Set();
  let sawHello, sawClose; const hello = new Promise((r) => { sawHello = r; }); const peerClosed = new Promise((r) => { sawClose = r; });
  const calls = [];
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => { sockets.delete(socket); sawClose(); });
    const lines = createInterface({ input: socket }); lines.on('error', () => {});
    lines.on('line', (line) => { const frame = JSON.parse(line); calls.push(frame.op); assert.equal(frame.op, 'hello'); assert.equal(frame.payload.token, 'TOKEN_CANARY'); sawHello(); });
    // Deliberately no hello response: no authenticated facade exists yet.
  });
  await new Promise((r) => server.listen(path, r));
  const controller = new AbortController(); const reason = new Error('MCP fixture EOF'); let connection; let bootstrap;
  const input = new PassThrough(); const output = new PassThrough(); let text = ''; output.on('data', (chunk) => { text += chunk; });
  const state = createMcpState({ env: {}, client: {} });
  // This only composes the public SDK with the MCP lifecycle hook. It does
  // not inject contracts into the production backend or relax its release pin.
  state.hqInbox = { async takeInbox() {
    bootstrap = connectMemberQueries({ memberSocket: path, memberToken: 'TOKEN_CANARY', signal: controller.signal, contracts: {
      record() { throw new Error('unexpected shared record in silent-hello fixture'); },
      admission() { throw new Error('unexpected admission in silent-hello fixture'); },
    } });
    connection = await bootstrap; return { event: null };
  } };
  let closed = 0;
  state.close = async () => { closed++; controller.abort(reason); await connection?.close(); };
  const running = runMcpServer({ state, input, output });
  try {
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: {} } } })}\n`);
    await within(hello, 'SDK never sent initial hello');
    input.end();
    await within(peerClosed, 'MCP EOF left silent initial SDK hello connected');
    await within(running, 'MCP EOF did not drain its aborted bootstrap');
    await assert.rejects(bootstrap, (error) => error === reason);
    assert.equal(closed, 1); assert.equal(connection, undefined); assert.deepEqual(calls, ['hello']);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal(sockets.size, 0); assert.equal(text.includes('TOKEN_CANARY'), false); assert.equal(text.includes(path), false);
    const reply = JSON.parse(text.trim()); assert.equal(reply.result.isError, true);
  } finally {
    controller.abort(reason); for (const socket of sockets) socket.destroy(); input.end(); await running.catch(() => {});
    await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true });
  }
});


// The public CLI dispatches a real agent-mcp child. Terminate only the
// configured command PID, so an orphaned bootstrap cannot pass this test.
test('actual agent-bot mcp SIGTERM closes its silent initial member socket', { timeout: 15000 }, async () => {
  const pin = JSON.parse(readFileSync(new URL('../identity/hq-member-contracts.json', import.meta.url))).release;
  const contracts = pinnedComponent('soul-contracts', pin.commit);
  const dir = mkdtempSync(join(tmpdir(), 'mcp-signal-')); const path = join(dir, 'member.sock'); const sockets = new Set();
  let helloResolve, helloReject, closedResolve;
  const hello = new Promise((resolve, reject) => { helloResolve = resolve; helloReject = reject; });
  const closed = new Promise((resolve) => { closedResolve = resolve; });
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {});
    socket.once('close', () => { sockets.delete(socket); closedResolve(); });
    const lines = createInterface({ input: socket }); lines.on('error', () => {});
    lines.once('line', (line) => { try {
      const frame = JSON.parse(line); assert.equal(frame.op, 'hello'); assert.equal(frame.payload.token, 'SIGNAL_TOKEN_CANARY'); helloResolve();
    } catch (error) { helloReject(error); } });
  });
  await new Promise((resolve) => server.listen(path, resolve));
  const child = spawn(fileURLToPath(new URL('../agent-bot', import.meta.url)), ['mcp'], { detached: true,
    env: { ...process.env, AGENT_BOT_SOULS_SOCKET: path, AGENT_BOT_SOULS_MEMBER_TOKEN: 'SIGNAL_TOKEN_CANARY', AGENT_BOT_SOUL_CONTRACTS: contracts }, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.on('data', (chunk) => { output += chunk; });
  const exited = new Promise((resolve, reject) => { child.once('exit', resolve); child.once('error', reject); });
  try {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: {} } } })}\n`);
    await within(hello, 'actual CLI never sent its initial member hello', 5000);
    assert.equal(child.kill('SIGTERM'), true);
    await within(Promise.all([exited, closed]), 'configured command termination orphaned its initial member socket', 5000);
    assert.equal(sockets.size, 0); assert.equal(output.includes('SIGNAL_TOKEN_CANARY'), false); assert.equal(output.includes(path), false);
  } finally {
    child.stdin.end();
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve)); rmSync(dir, { recursive: true, force: true });
  }
});
