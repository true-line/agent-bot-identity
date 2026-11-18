import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { runMachineCli } from '../cli/machine.mjs';
import { machineOwnerPresence } from '../identity/machine-owner-presence.mjs';

function fixture(t, settings = { keydTeamId: 'ABCDE12345' }) {
  const home = mkdtempSync(path.join(tmpdir(), 'machine-owner-'));
  t.after(() => rmSync(home, { force: true, recursive: true }));
  const config = path.join(home, 'config.json');
  writeFileSync(config, JSON.stringify({ settings }));
  return { env: { HOME: home, AGENT_BOT_CONFIG: config }, home, platform: 'darwin', checkPath() {}, terminalInput: false };
}

test('protected CLI requires the dedicated helper and the configured exact Developer ID', (t) => {
  const options = fixture(t);
  const calls = [];
  const proof = '{"public_key":"fixture","signature":"fixture"}\n';
  const exec = (bin, args, settings) => { calls.push({ bin, args, settings }); return proof; };
  assert.equal(machineOwnerPresence('approve-pairing', { ...options, exec }), proof);
  assert.deepEqual(calls.map(({ bin }) => bin), ['/usr/bin/codesign', '/usr/bin/codesign', '/usr/sbin/spctl',
    '/Applications/AgentBotOwnerPresence.app/Contents/MacOS/agent-bot-owner-presence']);
  for (const { args } of calls.slice(0, 2)) {
    assert.ok(args.includes('--strict'));
    const requirement = args.find((arg) => arg.startsWith('-R='));
    assert.match(requirement, /identifier "ai\.true-line\.agent-bot-owner-presence"/);
    assert.match(requirement, /subject\.OU\] = "ABCDE12345"/);
  }
  assert.deepEqual(calls.at(-1).args, ['approve-pairing']);
  assert.equal(calls.at(-1).settings.stdio[0], 'inherit');
  calls.length = 0;
  machineOwnerPresence('owner-public-key', { ...options, exec });
  assert.deepEqual(calls.at(-1).args, ['public-key']);
  assert.equal(calls.at(-1).settings.stdio[0], 'ignore');
});

test('refuses an absent or wildcard team, a writable installation and a failed assessment before invoking the helper', (t) => {
  const options = fixture(t);
  for (const settings of [{}, { keydTeamId: 'any-developer-id' }]) {
    assert.throws(() => machineOwnerPresence('owner-public-key', {
      ...fixture(t, settings), exec: assert.fail,
    }), /settings.keydTeamId/);
  }
  assert.throws(() => machineOwnerPresence('approve-pairing', {
    ...options, checkPath() { throw new Error('writable installation'); }, exec: assert.fail,
  }), /writable installation/);
  for (const rejectedCall of [1, 2, 3]) {
    let count = 0;
    assert.throws(() => machineOwnerPresence('approve-pairing', {
      ...options, exec() { if (++count === rejectedCall) throw new Error('refused'); },
    }), /could not verify/);
    assert.equal(count, rejectedCall);
  }
});

test('requires macOS and a piped challenge, and propagates a canceled owner prompt', (t) => {
  const options = fixture(t);
  assert.throws(() => machineOwnerPresence('owner-public-key', { ...options, platform: 'linux', exec: assert.fail }), /requires macOS/);
  assert.throws(() => machineOwnerPresence('approve-pairing', { ...options, terminalInput: true, exec: assert.fail }), /standard input/);
  assert.throws(() => machineOwnerPresence('approve-pairing', {
    ...options, exec(bin) { if (bin.startsWith('/Applications')) throw new Error('canceled'); },
  }), /canceled/);
});

test('normal machine route uses the signed helper once and writes only its stdout', async (t) => {
  const options = fixture(t);
  let output = '';
  const reply = '{"public_key":"fixture","signature":"fixture"}';
  let asked = 0;
  let gateAction;
  const code = await runMachineCli(['approve-pairing'], {
    ...options, stdout: { write(chunk) { output += chunk; } },
    gate(action, { consent }) { gateAction = action; return consent(); },
    ownerPresence(command) { assert.equal(command, 'approve-pairing'); asked++; return reply; },
  });
  assert.equal(code, 0);
  assert.equal(gateAction, 'machine-approve-pairing');
  assert.equal(asked, 1);
  assert.equal(output, reply + '\n');
  const gated = { ...options, env: { ...options.env, AGENT_BOT_ID: 'agent_example' }, ownerPresence: assert.fail };
  await assert.rejects(runMachineCli(['approve-pairing'], gated), /owner only/);
  const bad = { ...gated, gate: assert.fail, stderr: { write() {} } };
  assert.equal(await runMachineCli(['owner-public-key', '--repin'], bad), 1);
});

test('stable executable documents the protected approval commands', () => {
  const result = spawnSync(process.execPath, ['agent-bot.mjs', 'machine', '--help'], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /owner-public-key/);
  assert.match(result.stdout, /approve-pairing/);
});
