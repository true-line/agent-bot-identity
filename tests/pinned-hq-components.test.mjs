// Real Git, fake canary config only. No transport command or real credential
// is used: the effective-config oracle proves what a fetch would inherit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publicGit } from './helpers/pinned-hq-components.mjs';

test('public test Git excludes scoped headers and all inherited config sources', () => {
  const root = mkdtempSync(join(tmpdir(), 'public-git-canary-'));
  try {
    const global = join(root, 'global'); const system = join(root, 'system'); const included = join(root, 'included');
    const template = join(root, 'template'); mkdirSync(join(template, 'hooks'), { recursive: true });
    writeFileSync(global, `[http "https://github.com/"]\n\textraHeader = X-CANARY-GLOBAL: fake-only\n[include]\n\tpath = ${included.replaceAll('\\', '/')}\n`);
    writeFileSync(system, '[http "https://github.com/true-line/"]\n\textraHeader = X-CANARY-SYSTEM: fake-only\n');
    writeFileSync(included, '[credential]\n\thelper = CANARY_INCLUDED_HELPER\n');
    writeFileSync(join(template, 'config'), '[probe]\n\ttemplate = CANARY_TEMPLATE\n');
    writeFileSync(join(template, 'hooks', 'pre-commit'), 'CANARY_TEMPLATE_HOOK');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
    Object.assign(env, { GIT_CONFIG_GLOBAL: global, GIT_CONFIG_SYSTEM: system, GIT_CONFIG_NOSYSTEM: '0',
      GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/true-line/soul-contracts.git.extraHeader', GIT_CONFIG_VALUE_0: 'X-CANARY-INJECTED: fake-only',
      GIT_CONFIG_PARAMETERS: "'probe.parameters=CANARY_PARAMETERS'", GIT_TEMPLATE_DIR: template });
    // Anchor both config oracles in an owned repository, never a parent.
    publicGit(root, ['init', '-q', '--template='], { env });
    // The previous generic resets leave URL-scoped headers and other injected
    // config active. This control is limited to the disposable canary files.
    const control = execFileSync('git', ['-c', 'credential.helper=', '-c', 'http.extraHeader=', '-C', root, 'config', '--list'], { env, encoding: 'utf8' });
    for (const canary of ['X-CANARY-GLOBAL', 'X-CANARY-SYSTEM', 'X-CANARY-INJECTED', 'CANARY_PARAMETERS']) assert.ok(control.includes(canary), canary);
    const safe = publicGit(root, ['config', '--list', '--show-origin'], { env }).toString();
    assert.equal(safe.includes('CANARY'), false); assert.equal(safe.includes(global), false); assert.equal(safe.includes(system), false); assert.equal(safe.includes(included), false);
    assert.equal(publicGit(root, ['config', '--local', '--list'], { env }).toString().includes('CANARY'), false);
    assert.equal(existsSync(join(root, '.git', 'hooks', 'pre-commit')), false, 'init does not copy ambient templates');
    // All injection keys are stripped, including explicit config-path aliases.
    const explicit = publicGit(root, ['config', '--list'], { env: { ...env, GIT_CONFIG: global, GIT_CONFIG_UNUSED_CANARY: global } }).toString();
    assert.equal(explicit.includes('CANARY'), false); assert.equal(env.GIT_CONFIG_GLOBAL, global, 'caller environment is unchanged');
    // Repository context must not redirect -C into another checkout/config.
    // Every target is a fake nonexistent path owned by this disposable test.
    const redirected = { ...env, GIT_DIR: join(root, 'CANARY_OTHER_GIT'), GIT_COMMON_DIR: join(root, 'CANARY_COMMON'),
      GIT_WORK_TREE: join(root, 'CANARY_WORK_TREE'), GIT_INDEX_FILE: join(root, 'CANARY_INDEX'), GIT_OBJECT_DIRECTORY: join(root, 'CANARY_OBJECTS') };
    assert.equal(publicGit(root, ['rev-parse', '--absolute-git-dir'], { env: redirected }).toString().trim(), join(root, '.git'));
    assert.equal(publicGit(root, ['config', '--list'], { env: redirected }).toString().includes('CANARY'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
