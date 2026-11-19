import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { runMachineCli } from '../cli/machine.mjs';
import { approveFirstHQ, machineOwnerPresence } from '../identity/machine-owner-presence.mjs';

function fixture(t, settings = { keydTeamId: 'ABCDE12345' }) {
  const home = mkdtempSync(path.join(tmpdir(), 'machine-owner-'));
  t.after(() => rmSync(home, { force: true, recursive: true }));
  const config = path.join(home, 'config.json');
  writeFileSync(config, JSON.stringify({ settings }));
  return { env: { HOME: home, AGENT_BOT_CONFIG: config }, home, platform: 'darwin', terminalInput: false };
}

test('Machine owner commands refuse without creating local state when the owner provider is unavailable', async (t) => {
  const options = fixture(t);
  const refusal = { code: 'machine-owner-provider-unavailable', message: /New approvals must wait for a compatible provider/ };
  for (const command of ['owner-public-key', 'approve-pairing']) {
    assert.throws(() => machineOwnerPresence(command, options), refusal);
  }
  await assert.rejects(approveFirstHQ({}, options), refusal);
  assert.deepEqual(readdirSync(options.home), ['config.json']);
  assert.throws(() => machineOwnerPresence('owner-public-key', { ...options, platform: 'linux' }), /requires macOS/);
  assert.throws(() => machineOwnerPresence('approve-pairing', { ...options, terminalInput: true }), /standard input/);
  assert.throws(() => machineOwnerPresence('sign', options), /unknown Machine owner operation/);
});

test('normal machine route gates the typed owner operation and writes only its public response', async (t) => {
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
