// Test dependencies only. Public source, exact immutable commits, no runtime
// loader override, schema copies, credentials or moving-branch resolution.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
// A fresh fetch must not read an operator's Git config or inherited config
// injection. Existing cached repositories are only verified locally.
export function publicGit(directory, args, { env = process.env } = {}) {
  const clean = Object.fromEntries(Object.entries(env).filter(([name]) => !name.startsWith('GIT_')));
  const nullFile = process.platform === 'win32' ? 'NUL' : '/dev/null';
  return execFileSync('git', ['-c', 'credential.helper=', '-c', 'http.extraHeader=', '-C', directory, ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...clean, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_SYSTEM: nullFile, GIT_CONFIG_GLOBAL: nullFile,
      GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/false', SSH_ASKPASS: '/bin/false' },
  });
}
export function pinnedComponent(name, commit) {
  const root = fileURLToPath(new URL('../../node_modules/.cache/hq-member-components/', import.meta.url));
  mkdirSync(root, { recursive: true }); const dir = join(root, `${name}-${commit}`);
  const verify = (directory) => {
    if (publicGit(directory, ['rev-parse', 'HEAD']).toString().trim() !== commit
      || publicGit(directory, ['status', '--porcelain', '--untracked-files=no']).toString().trim()) {
      throw new Error(`test dependency ${name} is not the clean reviewed source`);
    }
  };
  if (!existsSync(dir)) {
    const stage = mkdtempSync(join(root, `.${name}-${commit}-`));
    try {
      publicGit(stage, ['init', '-q', '--template=']);
      publicGit(stage, ['fetch', '-q', '--depth', '1', `https://github.com/true-line/${name}.git`, commit]);
      publicGit(stage, ['checkout', '-q', 'FETCH_HEAD']);
      verify(stage);
      try { renameSync(stage, dir); }
      catch (error) {
        // Another process may publish a complete checkout first. Refuse any
        // other rename failure; the winner is validated again below.
        if (!['EEXIST', 'ENOTEMPTY'].includes(error.code)) throw error;
      }
    } finally { rmSync(stage, { recursive: true, force: true }); }
  }
  verify(dir);
  return dir;
}
