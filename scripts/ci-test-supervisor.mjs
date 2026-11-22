#!/usr/bin/env node
// A live process-group anchor for one CI test file. The coordinator releases
// this process only after receiving the child's result; a timed-out group is
// killed while its leader is still present, so its numeric PGID cannot be
// recycled between a process snapshot and the signal.
import { spawn } from 'node:child_process';

const file = process.argv[2];
if (!file || !process.send) throw new Error('CI test supervisor requires one file and an IPC parent');
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;
const test = spawn(process.execPath, ['--test', file], { stdio: ['ignore', 'pipe', 'pipe'], env });
test.stdout.pipe(process.stdout);
test.stderr.pipe(process.stderr);
let result;
let spawnError;
let released = false;
test.on('error', (error) => { spawnError = error; });
test.on('close', (code, signal) => {
  result = { kind: 'done', code, signal, error: spawnError?.code ?? null };
  process.send(result);
});
process.on('message', (message) => {
  if (message?.kind === 'timeout') {
    try {
      if (process.platform === 'win32') test.kill('SIGKILL');
      else process.kill(-process.pid, 'SIGKILL');
    } catch (error) { if (error.code !== 'ESRCH') process.stderr.write(`timeout kill failed: ${error.code ?? error.message}\n`); }
    process.exitCode = 1;
    return;
  }
  if (message?.kind !== 'release' || !result) return;
  released = true;
  process.exitCode = result.error || result.signal || result.code !== 0 ? 1 : 0;
  process.disconnect();
});
process.on('disconnect', () => {
  if (released) return;
  if (!result) { try { test.kill('SIGKILL'); } catch { /* already gone */ } }
  process.exitCode = 1;
});
