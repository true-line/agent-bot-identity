import { execFileSync } from 'node:child_process';
import { accessSync, constants, lstatSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { ANY_DEVELOPER_ID, keydSignerSetting, loadConfig } from '../config.mjs';
import { developerIdRequirement } from './owner-presence.mjs';

const APP = '/Applications/AgentBotOwnerPresence.app';
const PROGRAM = APP + '/Contents/MacOS/agent-bot-owner-presence';
const IDENTIFIER = 'ai.true-line.agent-bot-owner-presence';

// Verification and execution are separate OS operations. The approver's
// account must not be able to replace a checked executable or its ancestors.
function checkInstallPath() {
  for (let location = PROGRAM; location !== '/'; location = path.dirname(location)) {
    const info = lstatSync(location);
    if (info.uid === process.getuid()) throw new Error(`owner approval requires an independently installed app (${location})`);
    if (location === PROGRAM ? !info.isFile() : !info.isDirectory()) {
      throw new Error(`unexpected owner approval installation at ${location}`);
    }
    try {
      accessSync(location, constants.W_OK);
    } catch (error) {
      if (error.code === 'EACCES' || error.code === 'EPERM' || error.code === 'EROFS') continue;
      throw error;
    }
    throw new Error(`owner approval needs an installation this account cannot modify (${location})`);
  }
}

// The native helper owns input validation, the platform prompt and signing.
// Its success output is public JSON. Machine makes the enrollment decision.
export function machineOwnerPresence(command, {
  env, home, platform = process.platform, exec = execFileSync, checkPath = checkInstallPath,
  terminalInput = process.stdin.isTTY,
} = {}) {
  if (platform !== 'darwin') throw new Error('Machine owner approval requires macOS');
  if (command !== 'owner-public-key' && command !== 'approve-pairing') throw new Error('unknown Machine owner operation');
  if (command === 'approve-pairing' && terminalInput) throw new Error('provide the Machine pairing challenge JSON on standard input');
  const { teamId } = keydSignerSetting(loadConfig({ env, home }));
  if (!teamId || teamId === ANY_DEVELOPER_ID) throw new Error('Machine owner approval requires an exact settings.keydTeamId in the organization configuration');
  try {
    checkPath();
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`the separate Mac owner approval app is missing at ${APP}`);
    throw error;
  }
  const requirement = developerIdRequirement({ teamId, identifier: IDENTIFIER });
  const options = { env: { PATH: '/usr/bin:/bin', HOME: home }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 };
  try {
    exec('/usr/bin/codesign', ['--verify', '--strict', `-R=${requirement}`, APP], options);
    exec('/usr/bin/codesign', ['--verify', '--strict', `-R=${requirement}`, PROGRAM], options);
    exec('/usr/sbin/spctl', ['--assess', '--type', 'execute', APP], options);
  } catch (cause) {
    throw new Error('macOS could not verify the signed owner approval app', { cause });
  }
  return exec(PROGRAM, [command === 'owner-public-key' ? 'public-key' : command], {
    ...options, stdio: [command === 'approve-pairing' ? 'inherit' : 'ignore', 'pipe', 'inherit'],
    encoding: 'utf8', timeout: 150000, maxBuffer: 8192,
  });
}
