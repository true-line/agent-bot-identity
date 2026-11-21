import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { firstHQSignedBytes } from '../machine-first-hq.mjs';
import { existingMachinePin, pilotProvider, runPilot } from '../tools/private-pilot/machine-owner.mjs';

function disposableOwner() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { x, y } = pair.publicKey.export({ format: 'jwk' });
  const pin = Buffer.concat([Buffer.of(4), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')]).toString('base64');
  return { pin, proof: bytes => JSON.stringify({ public_key: pin, signature: sign('sha256', bytes, pair.privateKey).toString('base64') }) };
}

const helper = '/Applications/AgentBotOwnerPresence.app/Contents/MacOS/agent-bot-owner-presence';

function fixture(t) {
  const home = mkdtempSync(join(tmpdir(), 'existing-pilot-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const env = { HOME: home, AGENT_BOT_CONFIG: join(home, 'org.json') };
  writeFileSync(env.AGENT_BOT_CONFIG, JSON.stringify({ settings: { keydTeamId: 'ABCDE12345' } }));
  const owner = disposableOwner();
  const first = JSON.parse(readFileSync(new URL('./fixtures/first-hq-challenge.json', import.meta.url)));
  first.expires_at = Math.floor(Date.now() / 1000) + 90;
  const pair = { action: 'machine-pair', machine_key: '1'.repeat(64), hq_key: '2'.repeat(64),
    nonce: '3'.repeat(64), expires_at: first.expires_at };
  const bytes = Buffer.from('agent-bot-machine-owner/v1\nmachine-pair\n' + pair.machine_key + '\n' +
    pair.hq_key + '\n' + pair.nonce + '\n' + pair.expires_at + '\n');
  const checks = [];
  const signs = [];
  const providerOptions = {
    platform: 'darwin', checkPath() { checks.push('path'); },
    check(tool, args) {
      if (tool === '/usr/bin/codesign') {
        assert.match(args[2], /identifier "ai\.true-line\.agent-bot-owner-presence"/);
        assert.match(args[2], /subject\.OU\] = "ABCDE12345"/);
      }
      checks.push([tool, args.at(-1)]);
    },
    async sign(command, challenge) {
      signs.push(command);
      assert.deepEqual(challenge, command === 'approve-first-hq' ? first : pair);
      return owner.proof(command === 'approve-first-hq' ? firstHQSignedBytes(first) : bytes);
    },
  };
  return { owner, first, pair, bytes, env, home, checks, signs, providerOptions };
}

test('explicit private pilot uses its existing verified owner key for pairing and first-HQ', async t => {
  const f = fixture(t);
  let result = '';
  const cliOptions = { env: f.env, home: f.home, gate: (action, opts) => {
    assert.equal(action, 'machine-approve-pairing');
    return opts.consent();
  }, stdout: { write(s) { result += s; } } };
  const publicFile = join(f.home, 'confirmed-pilot-owner.pub');
  writeFileSync(publicFile, f.owner.pin + '\n');
  assert.equal(await runPilot(['--owner-pin-file', publicFile, 'approve-pairing'], {
    cliOptions, providerOptions: f.providerOptions, input: Readable.from([Buffer.from(JSON.stringify(f.pair))]),
  }), 0);
  assert.equal(JSON.parse(result).public_key, f.owner.pin);
  const approve = pilotProvider(f.owner.pin, f.providerOptions);
  assert.equal(JSON.parse(await approve('approve-first-hq', f.first, f)).public_key, f.owner.pin);
  const checks = ['path', ['/usr/bin/codesign', '/Applications/AgentBotOwnerPresence.app'],
    ['/usr/bin/codesign', helper], ['/usr/sbin/spctl', '/Applications/AgentBotOwnerPresence.app']];
  assert.deepEqual(f.checks, [...checks, ...checks]);
  assert.deepEqual(f.signs, ['approve-pairing', 'approve-first-hq']);
});

test('private pilot rejects a different owner, invalid signature, expired input, or unverifiable app', async t => {
  const f = fixture(t);
  const other = disposableOwner();
  for (const [command, challenge] of [['approve-pairing', f.pair], ['approve-first-hq', f.first]]) {
    await assert.rejects(pilotProvider(other.pin, f.providerOptions)(command, challenge, f), /existing Machine owner pin/);
    const changedProof = { ...f.providerOptions, sign: () => f.owner.proof(Buffer.from('other challenge')) };
    await assert.rejects(pilotProvider(f.owner.pin, changedProof)(command, challenge, f), /Invalid or expired/);
    await assert.rejects(pilotProvider(f.owner.pin, f.providerOptions)(command, { ...challenge, expires_at: 1 }, f));
  }
  const count = f.signs.length;
  for (const option of ['checkPath','check']) {
    const rejected = { ...f.providerOptions, [option]() { throw Error('unverified'); } };
    await assert.rejects(pilotProvider(f.owner.pin, rejected)('approve-pairing', f.pair, f), /unverified/);
  }
  writeFileSync(f.env.AGENT_BOT_CONFIG, '{"settings":{"keydTeamId":"any-developer-id"}}');
  await assert.rejects(pilotProvider(f.owner.pin, f.providerOptions)('approve-pairing', f.pair, f), /exact pilot publisher/);
  assert.equal(f.signs.length, count);
});

test('private pilot cannot create or read an owner key or select an arbitrary helper', async () => {
  for (const op of ['owner-public-key', 'public-key', 'init-owner-key', 'pair', 'authorize-first-enrollment', 'repair', '--helper']) {
    await assert.rejects(runPilot([op]), /Usage/);
  }
});

test('automatic lookup uses the prefix owner’s private Machine record only', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, t => {
  const f = fixture(t);
  const prefix = join(f.home, 'homebrew');
  const account = { uid: process.getuid(), homedir: f.home };
  mkdirSync(prefix);
  const dir = join(f.home, '.config', 'agent-machine');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const record = join(dir, 'owner-pair.json');
  writeFileSync(record, JSON.stringify({ owner: f.owner.pin }), { mode: 0o600 });
  assert.equal(existingMachinePin({ prefix, account }), f.owner.pin);
  assert.throws(() => existingMachinePin({ prefix, account: { ...account, uid: account.uid + 1 } }), /owner-pin-file/);
  chmodSync(record, 0o644);
  assert.throws(() => existingMachinePin({ prefix, account }), /Invalid owner pin file/);
  rmSync(record);
  const separate = join(f.home, 'unrelated');
  writeFileSync(separate, JSON.stringify({ owner: f.owner.pin }), { mode: 0o600 });
  symlinkSync(separate, record);
  assert.throws(() => existingMachinePin({ prefix, account }));
});
