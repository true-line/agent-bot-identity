// Real Git, fake canary config only. No transport command or real credential
// is used: the effective-config oracle proves what a fetch would inherit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, cpSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
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


// A held fetch deterministically overlaps two independent test processes.
// The wrapper rewrites only the fixed fixture URL to an owned local Git source.
test('cold component cache publishes only a verified checkout across concurrent processes', { timeout: 20000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'component-cache-race-'));
  const children = []; let stopped = false; const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const bounded = async (promise, message) => {
    let timer;
    try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), 5000); })]); }
    finally { clearTimeout(timer); }
  };
  try {
    const source = join(root, 'source'); mkdirSync(source);
    publicGit(source, ['init', '-q', '--template=']); writeFileSync(join(source, 'fixture'), 'owned immutable source\n');
    publicGit(source, ['add', 'fixture']);
    publicGit(source, ['-c', 'user.name=CANARY', '-c', 'user.email=canary@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'Owned fixture']);
    const commit = publicGit(source, ['rev-parse', 'HEAD']).toString().trim();
    const realGit = realpathSync(process.env.PATH.split(delimiter).map((dir) => join(dir, 'git')).find(existsSync));
    mkdirSync(join(root, 'tests/helpers'), { recursive: true }); mkdirSync(join(root, 'bin'));
    cpSync(new URL('./helpers/pinned-hq-components.mjs', import.meta.url), join(root, 'tests/helpers/pinned-hq-components.mjs'));
    writeFileSync(join(root, 'runner.mjs'), `import { pinnedComponent } from './tests/helpers/pinned-hq-components.mjs'; console.log(pinnedComponent('canary-source', ${JSON.stringify(commit)}));\n`);
    writeFileSync(join(root, 'bin/git'), `#!${process.execPath}
const fs=require('node:fs'),cp=require('node:child_process'),p=require('node:path');
(async()=>{const root=${JSON.stringify(root)},args=process.argv.slice(2);if(args.includes('fetch')){const url=args.indexOf('https://github.com/true-line/canary-source.git');if(url<0)throw Error('unexpected fixture URL');args[url]=${JSON.stringify(source)};let first=false;try{fs.writeFileSync(p.join(root,'fetch-entered'),'1',{flag:'wx'});first=true;}catch(e){if(e.code!=='EEXIST')throw e;}if(first){const until=Date.now()+10000;while(!fs.existsSync(p.join(root,'release-fetch'))){if(Date.now()>until)throw Error('owned fetch gate timed out');await new Promise(r=>setTimeout(r,10));}}}const r=cp.spawnSync(${JSON.stringify(realGit)},args,{env:process.env,stdio:'inherit'});process.exit(r.status??1);})();
`, { mode: 0o755 });
    const start = () => {
      const child = spawn(process.execPath, [join(root, 'runner.mjs')], { detached: true,
        env: { ...process.env, PATH: join(root, 'bin') + delimiter + process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = ''; let err = ''; child.stdout.on('data', (b) => { out += b; }); child.stderr.on('data', (b) => { err += b; });
      const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code) => resolve({ code, out, err })); });
      done.catch(() => {}); const running = { child, done }; children.push(running); return running;
    };
    const first = start();
    await bounded((async () => { while (!existsSync(join(root, 'fetch-entered'))) { if (stopped) throw new Error('owned fetch gate closed'); await wait(10); } })(), 'first process did not reach its held fetch');
    const final = join(root, 'node_modules/.cache/hq-member-components', `canary-source-${commit}`);
    const prematurelyVisible = existsSync(final);
    const second = start(); const secondResult = await bounded(second.done, 'second process did not independently finish its checkout');
    assert.equal(secondResult.code, 0, secondResult.err); assert.equal(prematurelyVisible, false, 'unfinished cache is never published');
    writeFileSync(join(root, 'release-fetch'), '1'); const firstResult = await bounded(first.done, 'concurrent loser did not accept the published winner');
    assert.equal(firstResult.code, 0, firstResult.err); assert.equal(firstResult.out.trim(), final); assert.equal(secondResult.out.trim(), final);
    assert.equal(publicGit(final, ['rev-parse', 'HEAD']).toString().trim(), commit); assert.equal(readFileSync(join(final, 'fixture'), 'utf8'), 'owned immutable source\n');
    assert.deepEqual(readdirSync(join(root, 'node_modules/.cache/hq-member-components')), [`canary-source-${commit}`], 'only the completed cache remains');
  } finally {
    stopped = true; writeFileSync(join(root, 'release-fetch'), '1');
    for (const { child } of children) { try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
    await Promise.allSettled(children.map(({ done }) => done)); rmSync(root, { recursive: true, force: true });
  }
});
