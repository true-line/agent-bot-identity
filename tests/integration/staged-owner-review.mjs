// Run outside the source tree with only the installed formula, its Node and a public test vector.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createECDH, createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const stage = process.argv[2];
const cli = join(stage, 'bin/agent-bot');
const lib = join(stage, 'opt/agent-bot/libexec');
const installed = (file) => import(pathToFileURL(join(lib, file)).href);
writeFileSync('invalid.json', '{}');
const invalid = spawnSync(cli, ['machine', 'review-first-hq', 'invalid.json'], { encoding: 'utf8', timeout: 15000 });
assert.equal(invalid.status, 1);
assert.match(invalid.stderr, /Invalid first-HQ challenge/);

assert.equal(typeof (await installed('gh-shim.mjs')).buildGhShim, 'function');
assert.match((await installed('keyd-client.mjs')).KEYD_PINNED_VERSION, /^\d+\.\d+\.\d+$/);
assert.ok(!existsSync(join(lib, 'keyd')), 'the Identity formula excludes the native keyd source');

const challenge = JSON.parse(readFileSync('first-hq-challenge.json', 'utf8'));
challenge.expires_at = Math.floor(Date.now() / 1000) + 90;
writeFileSync('challenge.json', JSON.stringify(challenge));
// Exercise the installed recovery command with fresh software keys and a v2 plan.
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const { membersPlanCanonical } = await installed('machine-members.mjs');
const { responseCanonical } = await installed('machine-client.mjs');
const machine = generateKeyPairSync('ed25519');
const machineKey = machine.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const directory = { path: '/Library/Application Support/ai.true-line.agent-bot-hq', action: 'create',
  owner: 'root', group: 'wheel', mode: '0755' };
const plist = '<plist><dict><key>SockPathName</key><string>' + directory.path + '/owner-control.sock</string></dict></plist>';
const release = { release_dir: '/Library/Example/hq', node: '/Library/Example/node', archive: '/Library/Example/hq.tar',
  artifact_sha256: 'ab'.repeat(32), node_sha256: 'cd'.repeat(32) };
const plan = JSON.parse(challenge.plan_canonical);
plan.steps[0].action = 'none';
plan.steps.push({ kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create', owner: 'operator',
  content: JSON.stringify({ service: release, plist, owner_uid: 501, runtime_directory: directory }), detail: 'Install the reviewed service' });
const canonical = membersPlanCanonical(plan);
const timestamp = Math.floor(Date.now() / 1000);
const body = { ...challenge, action: 'hq-service-recovery', machine_key: machineKey.toString('hex'),
  hq_key: 'ef'.repeat(32), owner_key: createECDH('prime256v1').generateKeys('base64'),
  plan_canonical: canonical, plan_digest: digest(canonical), expires_at: timestamp + 90 };
const frame = { ok: true, state: 'challenged', body, timestamp, nonce: 'fixture-reply', request_nonce: 'fixture-request' };
frame.signature = sign(null, responseCanonical(frame, Buffer.from(JSON.stringify(body))), machine.privateKey).toString('base64');
writeFileSync('recovery.json', JSON.stringify(frame) + '\n');

const terminal = spawnSync('/usr/bin/python3', ['-I', 'discard-owner-review.py', cli, 'machine', 'review-hq-service-recovery',
  'recovery.json', '--machine-fingerprint', digest(machineKey)], { encoding: 'utf8', timeout: 18000 });
assert.equal(terminal.status, 0, terminal.stderr);
const transcript = terminal.stdout;
assert.ok(transcript.includes('Service repair discarded.'), 'expected the installed repair review to discard');
const beforeConfirmation = transcript.replaceAll('\r', '').split('Type approve to request owner presence')[0];
assert.ok(beforeConfirmation.includes('Plan SHA-256 ' + body.plan_digest));
assert.ok(beforeConfirmation.includes('LaunchDaemon plist\n' + plist));
const display = beforeConfirmation.slice(beforeConfirmation.indexOf('\n{') + 1, beforeConfirmation.indexOf('\nLaunchDaemon plist\n'));
assert.deepEqual(JSON.parse(display).steps[1].content.runtime_directory, directory);

const { openFirstHQReview } = await installed('machine-first-hq-review.mjs');
async function checkBrowser(url) {
  const launch = new URL(url);
  // These are loaded lazily when the browser opens, after the CLI has started.
  for (const [asset, type] of [['./', 'text/html'], ['first-hq-session.js', 'text/javascript'],
    ['first-hq.js', 'text/javascript'], ['style.css', 'text/css']]) {
    const response = await fetch(new URL(asset, launch));
    assert.equal(response.status, 200, asset);
    assert.ok(response.headers.get('content-type')?.startsWith(type), asset);
    assert.ok((await response.text()).trim(), asset);
  }
  const post = (verb, bearer, body) => fetch(new URL(verb, launch), {
    method: 'POST', headers: { origin: launch.origin, authorization: 'Bearer ' + bearer, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const claim = await post('claim', launch.hash.slice(1), {});
  assert.equal(claim.status, 200);
  const { session, review } = await claim.json();
  assert.equal(review.plan_digest, challenge.plan_digest);
  assert.equal((await post('discard', session, { plan_digest: review.plan_digest })).status, 200);
}

let browserCheck;
try {
  const outcome = await openFirstHQReview('challenge.json', {
    signer: () => assert.fail('a discarded review requested a signer'),
    openBrowser(url) {
      browserCheck = checkBrowser(url);
      return browserCheck;
    },
  });
  assert.equal(outcome, 'discarded');
} finally {
  // The server finishes on the discard response. Wait for the client assertions too.
  await browserCheck;
}
console.log('Installed Homebrew wrapper, both owner review commands and browser assets passed.');
