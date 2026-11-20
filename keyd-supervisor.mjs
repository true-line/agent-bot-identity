#!/usr/bin/env node
// Supervising agent-bot-keyd under launchd (#397): the host side of keyd,
// beside the daemon's own supervisor. keyd-client.mjs keeps the protocol,
// grants and status; this file writes and loads the unit (#645).
//
//   agent-bot keyd install --bin PATH [--json]   supervise keyd under launchd
//   agent-bot keyd uninstall [--json]            unload it (its keys stay)
//   agent-bot keyd status [--json]               whether it answers, and the pin
import { execFileSync } from 'node:child_process';
import { closeSync, constants, existsSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { withLock } from './file-lock.mjs';
import { renderLaunchdPlist, supervisorSkipLoad } from './daemon-supervisor.mjs';
import {
  KEYD_LABEL, KEYD_LABEL_VARIABLE, keydPaths, keydStatus, keydVersionAction,
  vouchStateDir
} from './identity-host.mjs';

export function keydLabel(env = process.env) {
  const label = env[KEYD_LABEL_VARIABLE];
  if (label === undefined || label === '') return KEYD_LABEL;
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(label)) throw new Error(`${KEYD_LABEL_VARIABLE} must use letters, digits, dots, underscores or hyphens`);
  return label;
}

function unitPath(label, home) {
  return path.join(home, 'Library', 'LaunchAgents', `${label}.plist`);
}

function launchctl(args, env) {
  return execFileSync('/bin/launchctl', args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'], env });
}

const ownershipError = () => new Error('preserving the keyd LaunchAgent: its Identity installation record, plist and loaded job must agree. Manage a Machine-owned helper through its Machine installation');

function optionalFile(file) {
  let fd;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw ownershipError();
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o022) || stat.size > 64 * 1024) throw ownershipError();
    return { dev: stat.dev, ino: stat.ino, text: readFileSync(fd, 'utf8') };
  } finally {
    closeSync(fd);
  }
}

function checkFile(file, expected) {
  const actual = optionalFile(file);
  if (actual?.dev !== expected?.dev || actual?.ino !== expected?.ino || actual?.text !== expected?.text) throw ownershipError();
}

function registration(file) {
  const record = optionalFile(file);
  if (record === null) return null;
  let value;
  try { value = JSON.parse(record.text); } catch { throw ownershipError(); }
  const label = value?.label ?? KEYD_LABEL;
  if (typeof value?.bin !== 'string' || !path.isAbsolute(value.bin) ||
      typeof label !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(label)) throw ownershipError();
  return { bin: value.bin, label };
}

function plistFor(label, bin, state) {
  return renderLaunchdPlist({ programArguments: [bin, 'serve', '--state-dir', state], label });
}

// Inspect the top-level launchd fields. Nested service metadata and
// environment values are never a source of program or ownership evidence.
function loadedKeyd(exec, env, domain, label, unit, bin, state) {
  let info;
  try { info = exec(['print', `${domain}/${label}`], env); } catch (error) {
    if (error.status === 113 || error.status === 112) return false;
    throw ownershipError();
  }
  if (!bin || typeof info !== 'string') throw ownershipError();
  const lines = info.split('\n');
  const field = name => lines.filter(line => line.startsWith(`\t${name} = `));
  const args = field('arguments');
  const at = lines.indexOf('\targuments = {');
  const expectedArgs = [bin, 'serve', '--state-dir', state].map(arg => '\t\t'+arg);
  if (field('path').length !== 1 || field('path')[0] !== '\tpath = '+unit ||
      field('program').length !== 1 || field('program')[0] !== '\tprogram = '+bin ||
      args.length !== 1 || at < 0 || !expectedArgs.every((arg, i) => lines[at + i + 1] === arg) ||
      lines[at + expectedArgs.length + 1] !== '\t}') throw ownershipError();
  return true;
}

function changeKeyd({ bin, env, home, exec }) {
  const install = bin !== undefined;
  const paths = keydPaths({ env, home });
  const state = vouchStateDir({ env, home });
  const pendingPath = paths.record + '.pending';
  return withLock(path.join(home, '.agent-bot-keyd-lifecycle.lock'), 'keyd lifecycle', () => {
    const saved = registration(paths.record);
    const pending = registration(pendingPath);
    const label = install ? keydLabel(env) : saved?.label ?? pending?.label ?? keydLabel(env);
    if ((saved && saved.label !== label) || (pending && (pending.label !== label || install && pending.bin !== bin))) throw ownershipError();
    const unit = unitPath(label, home);
    const previous = optionalFile(unit);
    const owner = [saved, pending].find(record => record && previous?.text === plistFor(label, record.bin, state));
    if (previous !== null && !owner) throw ownershipError();
    const domain = `gui/${process.getuid()}`;
    const skipLoad = supervisorSkipLoad(env);
    const registered = () => {
      const gui = loadedKeyd(exec, env, domain, label, unit, owner?.bin, state);
      const user = loadedKeyd(exec, env, 'user/'+process.getuid(), label, unit, owner?.bin, state);
      if (user && !gui) throw ownershipError();
      return gui;
    };
    const loaded = registered();
    const desired = install ? plistFor(label, bin, state) : null;
    const changed = (previous?.text ?? null) !== desired;
    if (loaded && changed) {
      if (skipLoad) throw new Error('the verified keyd job is running; resume without skip-load to change it');
      checkFile(unit, previous);
      exec(['bootout', `${domain}/${label}`], env);
      if (registered()) throw new Error('keyd is still registered; retry after the verified job stops');
    }
    checkFile(unit, previous);
    if (!install) {
      if (previous !== null) rmSync(unit);
      if (pending) rmSync(pendingPath);
      if (saved) rmSync(paths.record);
      return { unloaded: previous !== null, label, unitPath: unit };
    }
    if (!changed && saved?.bin === bin && !pending) {
      if (!skipLoad && !loaded) exec(['bootstrap', domain, unit], env);
      checkFile(unit, previous);
      return { label, unitPath: unit, bin, changed, loaded: true };
    }
    mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
    mkdirSync(path.dirname(unit), { recursive: true });
    // Only the committed record enables keyd's relay. Keep a separate intent
    // so a failed or interrupted bootstrap can retry the exact owned unit.
    if (!pending) writeFileSync(pendingPath, JSON.stringify({ bin, label })+'\n', { flag: 'wx', mode: 0o600 });
    if (changed) {
      if (previous !== null) rmSync(unit);
      writeFileSync(unit, desired, { mode: 0o644, flag: 'wx' });
    }
    const installed = changed ? optionalFile(unit) : previous;
    if (installed?.text !== desired) throw ownershipError();
    if (!skipLoad && (!loaded || changed)) exec(['bootstrap', domain, unit], env);
    checkFile(unit, installed);
    renameSync(pendingPath, paths.record);
    return { label, unitPath: unit, bin, changed, loaded: true };
  }, { keepLiveOwners: true });
}

export function installKeyd({ bin, env = process.env, home = homedir(), platform = process.platform, exec = launchctl } = {}) {
  if (platform !== 'darwin') throw new Error('agent-bot-keyd runs only on macOS');
  if (typeof bin !== 'string' || !path.isAbsolute(bin) || !existsSync(bin)) throw new Error('--bin must be the absolute path of an agent-bot-keyd binary');
  return changeKeyd({ bin, env, home, exec });
}

export function uninstallKeyd({ env = process.env, home = homedir(), platform = process.platform, exec = launchctl } = {}) {
  if (platform !== 'darwin') return { unloaded: false, reason: 'unsupported-platform' };
  return changeKeyd({ env, home, exec });
}


const USAGE = 'usage: agent-bot keyd install --bin PATH [--json] | uninstall [--json] | status [--json]';

export async function keydCommand(argv, { env = process.env, home = homedir(), write = (text) => process.stdout.write(text) } = {}) {
  const [action, ...rest] = argv;
  const json = rest.includes('--json');
  const args = rest.filter((arg) => arg !== '--json');
  let result;
  if (action === 'install') {
    if (args.length !== 2 || args[0] !== '--bin') throw new Error(USAGE);
    result = installKeyd({ bin: args[1], env, home });
    if (!json) write(`agent-bot-keyd ${result.changed ? 'installed' : 'unchanged'}: ${result.label} (${result.bin})\n`);
  } else if (action === 'uninstall' && args.length === 0) {
    result = uninstallKeyd({ env, home });
    if (!json) write(result.unloaded ? 'agent-bot-keyd unloaded; its Keychain items stay\n' : 'agent-bot-keyd was not installed\n');
  } else if (action === 'status' && args.length === 0) {
    result = await keydStatus({ env, home });
    if (!json) {
      write(result.running ? `agent-bot-keyd ${result.version ?? 'unknown version'} running; daemon key ${result.pinned ? 'pinned' : 'not pinned'}\n` : 'agent-bot-keyd is not running\n');
      if (result.running && result.versionMatches !== true) write(`this agent-bot is pinned to agent-bot-keyd ${result.expectedVersion}; ${keydVersionAction(result)}\n`);
    }
  } else {
    throw new Error(USAGE);
  }
  if (json) write(`${JSON.stringify(result)}\n`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  keydCommand(process.argv.slice(2)).catch((error) => {
    if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify({ error: { code: error.code ?? 'keyd-failed', message: error.message } })}\n`);
    process.stderr.write(`agent-bot keyd: ${error.message}\n`);
    process.exitCode = 1;
  });
}
