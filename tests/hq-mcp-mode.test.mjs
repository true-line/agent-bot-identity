import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { createMcpState, handleMcpMessage, runMcpServer } from '../agent-mcp.mjs';
import { createHqInboxBackend, hasHqMemberEnvironment } from '../identity/hq-inbox-backend.mjs';
import { loadHqMemberContracts, verifyHqContractTree } from '../identity/hq-member-contracts.mjs';

const memberEnv = { AGENT_BOT_SOULS_SOCKET: '/private/SOCKET_CANARY', AGENT_BOT_SOULS_MEMBER_TOKEN: 'TOKEN_CANARY', AGENT_BOT_SOUL_CONTRACTS: '/private/MISSING_CONTRACTS_CANARY' };
const call = (state, name = 'take_inbox', args = {}) => handleMcpMessage(state, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'call_write_tool', arguments: { name, arguments: args } } });
const text = (result) => result.result.content.map((c) => c.text).join('\n');

// These are real production dependency refusals. They are not substitutes for
// the mandatory positive installed-process run using the genuine release.
test('member inbox is selected before any legacy construction/binding and cannot fall back', async () => {
  let constructions = 0; let legacyTakes = 0;
  const state = createMcpState({ env: memberEnv, legacyClientFactory: () => { constructions++; return { population: () => [], takeInbox() { legacyTakes++; } }; } });
  assert.equal(constructions, 0);
  const refused = await call(state);
  assert.equal(refused.result.isError, true); assert.match(text(refused), /inbox-contracts-unavailable/);
  assert.equal(constructions, 0); assert.equal(legacyTakes, 0); assert.equal(state.secret, null);
  const population = await handleMcpMessage(state, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'population', arguments: {} } });
  assert.equal(population.result.isError, undefined); assert.equal(constructions, 1, 'explicit unmigrated tool keeps its lazy legacy backend');
  assert.match(text(await call(state)), /inbox-contracts-unavailable/); assert.equal(legacyTakes, 0);
  for (const canary of Object.values(memberEnv)) assert.equal(JSON.stringify(refused).includes(canary), false);
  await state.close();
});

test('partial/empty member inputs refuse without falling through to standalone', async () => {
  for (const env of [{ AGENT_BOT_SOULS_SOCKET: 'SOCKET_CANARY' }, { AGENT_BOT_SOULS_MEMBER_TOKEN: 'TOKEN_CANARY' }, { AGENT_BOT_SOULS_BROKER: 'BROKER_CANARY' },
    { ...memberEnv, AGENT_BOT_SOULS_MEMBER_TOKEN: '' }, { ...memberEnv, AGENT_BOT_SOULS_SOCKET: '' }]) {
    let legacy = 0;
    const state = createMcpState({ env, legacyClientFactory: () => { legacy++; throw new Error('forbidden legacy construction'); } });
    const result = await call(state); assert.match(text(result), /inbox-no-live-runtime/); assert.equal(legacy, 0);
    await state.close();
  }
  const defaultBroker = createMcpState({ env: { ...memberEnv, AGENT_BOT_SOULS_BROKER: '' }, legacyClientFactory() { throw new Error('forbidden'); } });
  assert.match(text(await call(defaultBroker)), /inbox-contracts-unavailable/, 'empty optional broker uses default only with complete member inputs');
  await defaultBroker.close();
  assert.equal(hasHqMemberEnvironment({ AGENT_BOT_SOUL_CONTRACTS: '/data' }), false, 'a shared dependency directory alone is not a member binding');
});

test('selectors refuse before release/SDK effects; discovery and unrelated names stay compatible', async () => {
  const state = createMcpState({ env: memberEnv, legacyClientFactory() { throw new Error('forbidden'); } });
  for (const args of [{ harness: 'other' }, { repo: 'other/repo' }, { runtime_id: 'other' }, { count: 1 }, []]) assert.match(text(await call(state, 'take_inbox', args)), /inbox-bad-request/);
  const search = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'search_tools', arguments: {} } };
  assert.deepEqual(await handleMcpMessage(state, search), await handleMcpMessage(createMcpState({ env: {} }), search));
  await state.close();
});

test('backend closes idempotently before first use without opening a socket', async () => {
  const backend = createHqInboxBackend({ env: memberEnv });
  const first = backend.close(); assert.equal(backend.close(), first); await first;
  await assert.rejects(backend.takeInbox(), { code: 'inbox-unavailable' });
});

test('stdio EOF and stream errors close the held SDK owner', async () => {
  for (const failure of [false, true]) {
    const input = new PassThrough(); const output = new PassThrough(); let closed = 0;
    const state = createMcpState({ env: {}, client: {} }); state.close = async () => { closed++; };
    const running = runMcpServer({ state, input, output });
    if (failure) input.emit('error', new Error('stream failed')); else input.end();
    if (failure) await assert.rejects(running, /stream failed/); else await running;
    assert.equal(closed, 1);
  }
});

test('real existing CLI/MCP stdio process refuses a missing pinned dependency before SDK network effects', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hq-mcp-')); const socket = join(dir, 'member.sock'); let connections = 0;
  const server = createServer((s) => { connections++; s.destroy(); }); await new Promise((r) => server.listen(socket, r));
  const executable = fileURLToPath(new URL('../agent-bot', import.meta.url));
  const child = spawn(executable, ['mcp'], { cwd: dir, env: { ...process.env, AGENT_BOT_SOULS_SOCKET: socket, AGENT_BOT_SOULS_MEMBER_TOKEN: 'TOKEN_CANARY', AGENT_BOT_SOUL_CONTRACTS: join(dir, 'missing-contracts'), AGENT_BOT_DAEMON_STATE_PATH: join(dir, 'FORBIDDEN_LEGACY_STATE') }, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = ''; let err = ''; child.stdout.on('data', (b) => { out += b; }); child.stderr.on('data', (b) => { err += b; });
  const exit = new Promise((r, reject) => { child.once('error', reject); child.once('exit', (code) => r(code)); });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 10000);
  try {
    child.stdin.end(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })}\n${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: {} } } })}\n`);
    assert.equal(await exit, 0, err);
    const responses = out.trim().split('\n').map((s) => JSON.parse(s));
    assert.equal(responses.find((x) => x.id === 1).result.serverInfo.name, 'agent-bot');
    assert.match(text(responses.find((x) => x.id === 2)), /inbox-contracts-unavailable/);
    assert.equal(connections, 0); assert.equal(out.includes('TOKEN_CANARY'), false); assert.equal(out.includes(socket), false); assert.equal(err, '');
  } finally { clearTimeout(timeout); child.kill(); await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }); }
});

test('release declaration pins genuine v0.5.0 and no directory argument bypasses it', () => {
  const declaration = JSON.parse(readFileSync(new URL('../identity/hq-member-contracts.json', import.meta.url)));
  assert.equal(declaration.schema_version, 1); assert.equal(declaration.required_tag, 'v0.5.0');
  assert.equal(declaration.release.tag, 'v0.5.0'); assert.equal(declaration.release.commit, 'b96239cc47571237f7064ddbcbd0edec8e365c6b');
  assert.equal(declaration.release.digest, 'sha256:0927de7b4f3879c91a5b5a3057a579eefe38013b961b710514c0cd9f42226124'); assert.equal(declaration.release.files, 154);
  assert.throws(() => loadHqMemberContracts({ env: { AGENT_BOT_SOUL_CONTRACTS: '/arbitrary/contract/tree' } }), { code: 'inbox-contracts-unavailable' });
  assert.throws(() => verifyHqContractTree('/anything', { tag: 'v0.5.0' }), { code: 'inbox-contracts-unavailable' });
});

test('vendored SDK modules and license match the recorded reviewed-source hashes', () => {
  const root = fileURLToPath(new URL('../identity/vendor/agent-bot-sdk/', import.meta.url));
  const source = JSON.parse(readFileSync(join(root, 'source.json')));
  assert.equal(source.commit, '42d6f5110019f4b7d835e139875b89a75230afe1'); assert.equal(source.repository, 'https://github.com/true-line/agent-bot-hq');
  assert.equal(source.status, 'merged'); assert.equal(source.reviewed_pull, 139);
  const walk = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(join(dir, e.name), `${prefix}${e.name}/`) : [`${prefix}${e.name}`]);
  assert.deepEqual(walk(root).filter((p) => p.endsWith('.mjs')).sort(), Object.keys(source.files).map((p) => p.slice(4)).sort());
  for (const [path, hash] of Object.entries(source.files)) assert.equal(createHash('sha256').update(readFileSync(join(root, path.slice(4)))).digest('hex'), hash, path);
  assert.equal(createHash('sha256').update(readFileSync(join(root, 'LICENSE'))).digest('hex'), source.license_sha256);
});
