import { execFile, execFileSync } from 'node:child_process';
import { accessSync, constants, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
import { promisify } from 'node:util';
import { ANY_DEVELOPER_ID, keydSignerSetting, loadConfig } from '../config.mjs';
import { developerIdRequirement } from './owner-presence.mjs';

const identifier = 'ai.true-line.agent-bot-owner-presence';
const executable = '/Library/PrivilegedHelperTools/' + identifier;
const execAsync = promisify(execFile);

function unavailable(cause) {
  return Object.assign(new Error('The signed Machine owner helper or its protected credential is unavailable. Keep the existing owner pin.', { cause }), {
    code: 'machine-owner-provider-unavailable',
  });
}

function checkInstallation() {
  for (let p = executable; ; p = dirname(p)) {
    const stat = lstatSync(p);
    if (stat.uid !== 0 || (p === executable ? !stat.isFile() : !stat.isDirectory())) throw unavailable();
    try {
      accessSync(p, constants.W_OK);
    } catch (error) {
      if (!['EACCES', 'EPERM', 'EROFS'].includes(error.code)) throw error;
      if (p === '/') break;
      continue;
    }
    throw unavailable();
  }
}

function verifiedOptions({ env, home, checkPath = checkInstallation, exec = execFileSync }) {
  const options = { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8', timeout: 15000, maxBuffer: 8192 };
  try {
    checkPath();
    const { teamId } = keydSignerSetting(loadConfig({ env, home }));
    if (!teamId || teamId === ANY_DEVELOPER_ID) throw unavailable();
    const requirement = developerIdRequirement({ teamId, identifier });
    exec('/usr/bin/codesign', ['--verify', '--strict', '--check-notarization', '-R=notarized and ' + requirement, executable],
      { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    throw unavailable(error);
  }
  return { ...options, timeout: 150000 };
}

export function machineOwnerPresence(command, {
  platform = process.platform, terminalInput = process.stdin.isTTY, exec = execFileSync, ...options
} = {}) {
  if (platform !== 'darwin') throw new Error('Machine owner approval requires macOS');
  if (!['init-owner-key', 'owner-public-key', 'approve-pairing'].includes(command)) throw new Error('unknown Machine owner operation');
  if (command === 'approve-pairing' && terminalInput) throw new Error('provide the Machine pairing challenge JSON on standard input');
  return exec(executable, [command], {
    ...verifiedOptions({ ...options, exec }), stdio: [command === 'approve-pairing' ? 'inherit' : 'ignore', 'pipe', 'inherit'],
  });
}

async function signFirstHQ(input, options) {
  const child = execAsync(executable, ['approve-first-hq'], options);
  child.child.stdin.on('error', () => {});
  child.child.stdin.end(input);
  return (await child).stdout;
}

export async function approveFirstHQ(challenge, { platform = process.platform, signal, sign = signFirstHQ, ...options } = {}) {
  if (platform !== 'darwin') throw new Error('Machine owner approval requires macOS');
  const childOptions = { ...verifiedOptions(options), signal };
  try {
    return await sign(JSON.stringify(challenge), childOptions);
  } catch (error) {
    if ([69, 'ENOENT', 'EACCES', 'ENOEXEC'].includes(error.code)) throw unavailable(error);
    throw error;
  }
}
