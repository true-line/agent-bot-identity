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
  options.checkPath = () => { throw new Error('not installed'); };
  const refusal = { code: 'machine-owner-provider-unavailable', message: /signed Machine owner helper or its protected credential is unavailable/ };
  for (const command of ['init-owner-key', 'owner-public-key', 'approve-pairing']) {
    assert.throws(() => machineOwnerPresence(command, options), refusal);
  }
  await assert.rejects(approveFirstHQ({}, options), refusal);
  assert.deepEqual(readdirSync(options.home), ['config.json']);
  assert.throws(() => machineOwnerPresence('owner-public-key', { ...options, platform: 'linux' }), /requires macOS/);
  assert.throws(() => machineOwnerPresence('approve-pairing', { ...options, terminalInput: true }), /standard input/);
  assert.throws(() => machineOwnerPresence('sign', options), /unknown Machine owner operation/);
});

test('daily operations use only the verified installed executable and the selected command', async (t) => {
  const options = fixture(t);
  const helper = '/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence';
  const calls = [];
  options.checkPath = () => calls.push('path');
  options.exec = (file, args, child) => {
    calls.push(file);
    if (file === '/usr/bin/codesign') {
      assert.ok(args.includes('--check-notarization'));
      assert.match(args.at(-2), /ABCDE12345/);
      assert.match(args.at(-2), /identifier "ai\.true-line\.agent-bot-owner-presence"/);
      assert.equal(args.at(-1), helper);
      return '';
    }
    assert.equal(file, helper);
    assert.deepEqual(args, [command]);
    assert.equal(child.stdio[0], command === 'approve-pairing' ? 'inherit' : 'ignore');
    assert.deepEqual(child.env, { PATH: '/usr/bin:/bin' });
    return 'public result';
  };
  let command;
  for (command of ['owner-public-key', 'init-owner-key', 'approve-pairing']) {
    calls.length = 0;
    assert.equal(machineOwnerPresence(command, options), 'public result');
    assert.deepEqual(calls, ['path', '/usr/bin/codesign', helper]);
  }
  const controller = new AbortController();
  const challenge = { nonce: 'example' };
  const reply = await approveFirstHQ(challenge, {
    ...options, signal: controller.signal, sign(input, child) {
      assert.deepEqual(JSON.parse(input), challenge);
      assert.equal(child.signal, controller.signal);
      return 'public proof';
    },
  });
  assert.equal(reply, 'public proof');
  let invoked = false;
  const bad = { ...options, exec() { throw new Error('untrusted signer'); }, sign() { invoked = true; } };
  await assert.rejects(approveFirstHQ(challenge, bad), { code: 'machine-owner-provider-unavailable' });
  assert.equal(invoked, false);
});

test('first HQ distinguishes a missing credential from a declined request', async (t) => {
  const options = { ...fixture(t), checkPath() {}, exec() {} };
  for (const code of [69, 'ENOENT', 1, 'ABORT_ERR']) {
    const error = Object.assign(new Error('native refusal'), { code });
    const request = approveFirstHQ({}, { ...options, sign: async () => { throw error; } });
    if (code === 69 || code === 'ENOENT') {
      await assert.rejects(request, { code: 'machine-owner-provider-unavailable' });
    } else {
      await assert.rejects(request, (reason) => reason === error);
    }
  }
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
