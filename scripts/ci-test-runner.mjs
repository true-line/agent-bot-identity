#!/usr/bin/env node
// Run the same top-level test files as `npm test`, while recording which file
// and process is still active if CI's complete suite reaches its time bound.
import { spawn, execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_TIMEOUT_MS = 25 * 60 * 1000; // below the 30-minute Actions job limit
const DEFAULT_CONCURRENCY = Math.max(1, Math.min(8, availableParallelism()));
const SUPERVISOR = fileURLToPath(new URL('./ci-test-supervisor.mjs', import.meta.url));
const timestamp = () => new Date().toISOString();
// Match the shell's tests/*.mjs expansion: omit hidden names, include links
// and directories so an unusable match fails instead of disappearing.
export const testFiles = (directory = resolve('tests')) => readdirSync(directory)
  .filter((name) => !name.startsWith('.') && name.endsWith('.mjs'))
  .map((name) => join(directory, name)).sort();

function processSnapshot(pids) {
  try {
    // Show names and process-group membership, never command arguments or env.
    const rows = execFileSync('ps', ['-eo', 'pid,ppid,pgid,comm'], { encoding: 'utf8', timeout: 2000, maxBuffer: 2 * 1024 * 1024 }).split('\n');
    const groups = new Set(pids);
    return rows.filter((row, index) => index === 0 || groups.has(Number(row.trim().split(/\s+/)[2]))).join('\n');
  } catch (error) { return `process snapshot unavailable: ${error.code ?? error.message}`; }
}

export async function runSuite({ files = testFiles(), concurrency = DEFAULT_CONCURRENCY,
  timeoutMs = DEFAULT_TIMEOUT_MS, write = (line) => process.stdout.write(line) } = {}) {
  if (!Array.isArray(files) || files.length === 0 || files.some((file) => typeof file !== 'string' || !file)) throw new TypeError('test file list is empty or invalid');
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError('invalid CI test bounds');
  const active = new Map();
  let next = 0;
  let completed = 0;
  let failures = 0;
  let timedOut = false;
  const log = (line) => write(`[${timestamp()}] ${line}\n`);
  return new Promise((resolveResult) => {
    let resolved = false;
    const finish = (code) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(watchdog);
      log(`SUMMARY files=${files.length} completed=${completed} failures=${failures} timeout=${timedOut}`);
      resolveResult(code);
    };
    const watchdog = setTimeout(() => {
      timedOut = true;
      failures++;
      const groups = [...active].filter(([, item]) => !item.result && !item.exited).map(([pid]) => pid).filter((pid) => pid > 0);
      log(`TIMEOUT active=${[...active].map(([pid, item]) => `${item.file}:${pid}`).join(',')}`);
      log(processSnapshot(groups));
      // Each still-live supervisor kills its own group. The coordinator never
      // signals a numeric PGID after the potentially blocking ps snapshot.
      for (const pid of groups) {
        const item = active.get(pid);
        if (item?.child.connected) item.child.send({ kind: 'timeout' }, (error) => {
          if (error) log(`TIMEOUT_SIGNAL_FAILED file=${item.file} pid=${pid} error=${error.code ?? error.message}`);
        });
      }
      if (active.size === 0) finish(1);
      else setTimeout(() => finish(1), 1000);
    }, timeoutMs);
    const startNext = () => {
      while (!timedOut && active.size < concurrency && next < files.length) {
        const file = files[next++];
        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;
        const child = spawn(process.execPath, [SUPERVISOR, file], { detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe', 'ipc'], env });
        const pid = child.pid ?? -next;
        const item = { child, file, result: null, exited: false };
        active.set(pid, item);
        log(`START file=${file} pid=${pid}`);
        child.stdout.on('data', (chunk) => write(`[${file}] ${chunk}`));
        child.stderr.on('data', (chunk) => write(`[${file} stderr] ${chunk}`));
        let spawnError;
        child.on('error', (error) => { spawnError = error; });
        child.on('message', (message) => {
          if (message?.kind !== 'done' || item.result) return;
          item.result = message;
          child.send({ kind: 'release' });
        });
        child.on('exit', () => { item.exited = true; });
        child.on('close', (code, signal) => {
          active.delete(pid);
          completed++;
          if (spawnError || !item.result || item.result.error || item.result.code !== 0 || item.result.signal || code !== 0 || signal) failures++;
          log(`END file=${file} pid=${pid} code=${item.result?.code ?? code ?? 'null'} signal=${item.result?.signal ?? signal ?? 'none'}${spawnError || item.result?.error ? ` spawn_error=${spawnError?.code ?? item.result?.error ?? spawnError?.message}` : ''}`);
          if (timedOut) return;
          if (completed === files.length) finish(failures ? 1 : 0);
          else startNext();
        });
      }
    };
    startNext();
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const deadline = process.env.AGENT_BOT_CI_DEADLINE_EPOCH;
  const timeoutMs = deadline === undefined ? DEFAULT_TIMEOUT_MS : Number(deadline) * 1000 - Date.now();
  process.exitCode = await runSuite({ timeoutMs: Math.max(1, Math.floor(timeoutMs)) });
}
