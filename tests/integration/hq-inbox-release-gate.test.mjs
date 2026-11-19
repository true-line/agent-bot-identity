// Required, never-skipped acceptance. No production dependency override: an
// missing/tampered real release stops this run before installation or sockets.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { loadHqMemberContracts } from '../../identity/hq-member-contracts.mjs';
import { installExecutable } from '../../install.mjs';
import { pinnedComponent } from '../helpers/pinned-hq-components.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const load = (root, path) => import(pathToFileURL(join(root, path)).href);
test('installed existing MCP command inherits real Soul binding and consumes durable HQ custody once', { timeout: 60000 }, async () => {
  let contracts;
  try {
    const declaration = JSON.parse(readFileSync(join(ROOT, 'identity/hq-member-contracts.json')));
    assert.equal(declaration.release?.tag, 'v0.5.0');
    const directory = pinnedComponent('soul-contracts', declaration.release.commit);
    contracts = loadHqMemberContracts({ env: { AGENT_BOT_SOUL_CONTRACTS: directory } });
  }
  catch (error) { assert.fail(`PENDING REQUIRED ACCEPTANCE: actual installed MCP -> real Soul/HQ/comms proof is blocked by ${error.code}; provide the reviewed genuine v0.5.0 offline dependency. No source/callback override or skipped acceptance is permitted.`); }
  const sdk = JSON.parse(readFileSync(join(ROOT, 'identity/vendor/agent-bot-sdk/source.json')));
  const hqRoot = pinnedComponent('agent-bot-hq', sdk.commit);
  const commsRoot = pinnedComponent('agent-bot-comms', '972fcbed06c8ff79bf60bd9129f5da54e22f5772');
  const soulsRoot = pinnedComponent('agent-bot-souls', '699ea4a02028a6219695e9a64d4e7cdf3836be01');
  const { startHQ, SOUL, DIGEST, fakeLegacy } = await load(hqRoot, 'tests/hq-harness.mjs');
  const { legacySigner } = await load(hqRoot, 'hq/legacy.mjs');
  const { noticesPlugin } = await load(hqRoot, 'hq/notices.mjs');
  const { brokerPlugin } = await load(commsRoot, 'lib/hq-plugin/broker.mjs');
  const { startSoul } = await load(soulsRoot, 'lib/entry-point.mjs');
  const { prepareContracts } = await load(soulsRoot, 'scripts/prepare-contracts.mjs');
  const { DEFAULT_CONTRACTS_DIRECTORY } = await load(soulsRoot, 'lib/contracts.mjs');
  const runtimeContracts = await prepareContracts({ directory: DEFAULT_CONTRACTS_DIRECTORY });
  const schemas = Object.fromEntries(['notice-query', 'notice-result'].map((name) => [name, JSON.parse(readFileSync(join(contracts.directory, 'schemas/hq/v1', `${name}.schema.json`)))]));
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'hq-installed-'))); let hq; let soul;
  try {
    const artifact = join(home, 'runtime');
    cpSync(ROOT, artifact, { recursive: true, filter: (path) => {
      const parts = relative(ROOT, path).split('/'); return !parts.some((p) => ['.git', '.guard', 'node_modules', 'tests', 'tools', 'governance', 'Formula', 'dist', 'target'].includes(p)) && !parts.some((p) => p.startsWith('.env'));
    } });
    for (const [path, hash] of Object.entries(sdk.files)) assert.equal(createHash('sha256').update(readFileSync(join(artifact, 'identity/vendor/agent-bot-sdk', path.slice(4)))).digest('hex'), hash);
    const installed = installExecutable({ home, entrypoint: join(artifact, 'agent-bot'), embeddingApp: null, linuxBundle: null });
    assert.equal(realpathSync(installed), join(artifact, 'agent-bot'));
    const version = spawnSync(installed, ['--version'], { encoding: 'utf8', timeout: 10000 }); assert.equal(version.status, 0, version.stderr);
    const packageVersion = JSON.parse(readFileSync(join(artifact, 'package.json'))).version; assert.equal(version.stdout.trim(), packageVersion);
    const configFile = join(home, 'mcp.json'); writeFileSync(configFile, JSON.stringify({ command: installed, args: ['mcp'], env: { AGENT_BOT_SOUL_CONTRACTS: contracts.directory } }));
    const harness = 'notice-bot'; const repo = 'Example/Project'; const calls = []; let releaseTake;
    const take = new Promise((r) => { releaseTake = r; });
    const content = { repo, text: 'External untrusted content', event: 'issues', createdAt: 1794000000123 };
    hq = await startHQ({ config: { acceptedDefinitions: { [SOUL]: [DIGEST] }, notices: { harnesses: [harness], scopes: [{ soul_id: SOUL, definition_digest: DIGEST, member_id: 'm_lead', adapter_id: 'fixture-adapter', role: 'lead', harness, repo }] } },
      enrollment: { ...legacySigner({ run: fakeLegacy().run }), allowsHarness: (h) => h === harness },
      identity: { async call(_method, route, body) { calls.push(route); if (route.endsWith('/take')) { await take; return { status: 200, body: { harness, notices: [{ id: 'notice:one', ...content, lease: 'notice:one.LEASE_CANARY' }] } }; } const stored = JSON.parse(readFileSync(join(hq.home, 'store.json'))).tables.find(([name]) => name === 'agent-comms\0notice_mailbox')[1]; assert.ok(stored.some(([, row]) => row.message_id === 'notice:one' && row.state === 'ready'), 'ACK follows durable custody'); return { status: 200, body: { acked: [body.ids[0].split('.')[0]], stale: [], missing: [] } }; } },
      plugins: [brokerPlugin({ noticeTimers: { setTimer: () => ({ unref() {} }), clearTimer() {} } }), noticesPlugin({ schemas })] });
    const mailbox = hq.hq.host.provided('agent-comms').notices; releaseTake(); await mailbox.pull();
    const root = join(home, 'soul'); mkdirSync(join(root, 'Contents/host'), { recursive: true });
    for (const [path, value] of Object.entries({ 'SoulInfo.json': { soul_id: SOUL, members: [{ member_id: 'm_lead', role: 'lead', adapter_id: 'fixture-adapter', adapter_version: '0.1.0' }] }, 'SoulLock.json': { definition_digest: DIGEST }, 'host/adapters.json': { 'fixture-adapter': { command: [process.execPath, join(ROOT, 'tests/helpers/hq-inbox-acp-adapter.mjs')], env: { TEST_HQ_MCP_CONFIG: configFile } } } })) writeFileSync(join(root, 'Contents', path), JSON.stringify(value));
    soul = await startSoul({ root, hqHome: hq.home, renewEveryMs: 0, env: { ...process.env, AGENT_BOT_SOUL_CONTRACTS: runtimeContracts.directory ?? runtimeContracts } });
    const beforeCalls = calls.length; const chunks = []; await soul.prompt('exercise the existing MCP configuration', (chunk) => chunks.push(chunk));
    const result = JSON.parse(chunks.join('')); const value = (r) => JSON.parse(r.result.content[0].text);
    assert.deepEqual(result.listed.result.tools.map((tool) => tool.name), ['search_tools', 'describe_tool', 'call_tool', 'call_write_tool']);
    assert.ok(value(result.searched).some((tool) => tool.name === 'take_inbox')); assert.equal(value(result.described).name, 'take_inbox'); assert.equal(value(result.described).class, 'write');
    assert.deepEqual(value(result.one), { event: { id: 'notice:one', ...content, pulled: true } }); assert.deepEqual(value(result.empty), { event: null });
    assert.equal(result.forged.result.isError, true); assert.match(result.forged.result.content[0].text, /inbox-bad-request/);
    assert.equal(calls.length, beforeCalls); assert.deepEqual(await mailbox.peek({ harness, repo }), []);
    const row = hq.hq.core.tables.get('agent-comms\0notice_mailbox').get(`${harness}:notice:one`); assert.equal(row.state, 'consumed'); assert.equal(Object.hasOwn(row, 'notice'), false);
    console.log(JSON.stringify({ packageVersion, sdkSource: sdk.commit, installedExecutable: true, realMemberEnvironment: true, actualCliMcp: true, automaticAcpSlot: false, queryUpstreamCalls: 0, scope: 'protocol fixture adapter, not all harnesses or production activation' }));
  } finally { await soul?.stop(); await hq?.done(); rmSync(home, { recursive: true, force: true }); }
});
