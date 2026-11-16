// Test dependencies only. Public source, exact immutable commits, no runtime
// loader override, schema copies, credentials or moving-branch resolution.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
export function pinnedComponent(name, commit) {
  const root = fileURLToPath(new URL('../../node_modules/.cache/hq-member-components/', import.meta.url));
  mkdirSync(root, { recursive: true }); const dir = join(root, `${name}-${commit}`);
  const git = (...args) => execFileSync('git', ['-c', 'credential.helper=', '-c', 'http.extraHeader=', '-C', dir, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/false' } });
  if (!existsSync(dir)) {
    mkdirSync(dir); git('init', '-q'); git('fetch', '-q', '--depth', '1', `https://github.com/true-line/${name}.git`, commit); git('checkout', '-q', 'FETCH_HEAD');
  }
  if (git('rev-parse', 'HEAD').toString().trim() !== commit || git('status', '--porcelain', '--untracked-files=no').toString().trim()) throw new Error(`test dependency ${name} is not the clean reviewed source`);
  return dir;
}
