import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSuite, testFiles } from '../scripts/ci-test-runner.mjs';

test('CI file selection includes shell-glob links and excludes hidden names', { skip: process.platform === 'win32' }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-bot-ci-runner-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'real.mjs'), '');
  writeFileSync(join(dir, '.hidden.mjs'), '');
  symlinkSync('real.mjs', join(dir, 'linked.mjs'));
  assert.deepEqual(testFiles(dir), [join(dir, 'linked.mjs'), join(dir, 'real.mjs')]);
});

test('CI diagnostics run every file and report its PID and result', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-bot-ci-runner-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const pass = join(dir, 'pass.mjs'), fail = join(dir, 'fail.mjs');
  writeFileSync(pass, "import { test } from 'node:test'; test('pass', () => {});\n");
  writeFileSync(fail, "import { test } from 'node:test'; test('fail', () => { throw new Error('fixture refusal'); });\n");
  let output = '';
  const code = await runSuite({ files: [pass, fail], concurrency: 2, timeoutMs: 10_000, write: (line) => { output += line; } });
  assert.equal(code, 1);
  for (const file of [pass, fail]) {
    assert.match(output, new RegExp(`START file=${file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} pid=\\d+`));
    assert.match(output, new RegExp(`END file=${file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} pid=\\d+`));
  }
  assert.match(output, /SUMMARY files=2 completed=2 failures=1 timeout=false/);
});

test('CI diagnostics bound a stuck file and identify the active process', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-bot-ci-runner-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const hang = join(dir, 'hang.mjs');
  writeFileSync(hang, 'setInterval(() => {}, 1000);\n');
  let output = '';
  const before = Date.now();
  const code = await runSuite({ files: [hang], concurrency: 1, timeoutMs: 300,
    write: (line) => { output += line; } });
  assert.equal(code, 1);
  assert.ok(Date.now() - before < 5000, 'the watchdog did not bound the hanging test');
  assert.match(output, /TIMEOUT active=.*hang\.mjs:\d+/);
  assert.match(output, /SUMMARY files=1 completed=1 failures=/);
});

test('CI timeout kills a descendant with the owned test group', { skip: process.platform === 'win32' }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-bot-ci-runner-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const hang = join(dir, 'descendant.mjs'), pidFile = join(dir, 'descendant.pid');
  writeFileSync(hang, `import { spawn } from 'node:child_process';\nimport { writeFileSync } from 'node:fs';\nconst child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"], { stdio: 'ignore' });\nwriteFileSync(${JSON.stringify(pidFile)}, String(child.pid));\nsetInterval(() => {}, 1000);\n`);
  let output = '';
  const code = await runSuite({ files: [hang], concurrency: 1, timeoutMs: 3000,
    write: (line) => { output += line; } });
  assert.equal(code, 1);
  assert.match(output, /TIMEOUT active=.*descendant\.mjs:\d+/);
  const pid = Number(readFileSync(pidFile, 'utf8'));
  t.after(() => { try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } });
  let state = '';
  try { state = execFileSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).trim(); }
  catch { /* no process is the expected result */ }
  assert.ok(!state || state.startsWith('Z'), `descendant still running: ${state}`);
});
