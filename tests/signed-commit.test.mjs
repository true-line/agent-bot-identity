import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  assertLease,
  encodeRefPath,
  parseSignedCommitArgs,
  repositoryFromRemote,
  runSignedCommit,
} from '../signed-commit.mjs';
import { createBlob } from '../signed-commit.mjs';

const helloBlobSha = 'ce013625030ba8dba906f756967f9e9ca394464a';
const httpError = (status) => Object.assign(new Error(`HTTP ${status}`), { status });

test('signed-commit recovers an HTTP 500 blob creation only after exact SHA and byte read-back', async () => {
  const calls = [];
  const content = Buffer.from('hello\n');
  const api = async (path, method) => {
    calls.push([path, method ?? 'GET']);
    if (method === 'POST') throw httpError(500);
    return { sha: helloBlobSha, size: content.length, encoding: 'base64', content: 'aGVs\nbG8K\n' };
  };
  assert.deepEqual(await createBlob(api, 'acme/widgets', content), { sha: helloBlobSha });
  assert.deepEqual(calls, [
    ['repos/acme/widgets/git/blobs', 'POST'],
    [`repos/acme/widgets/git/blobs/${helloBlobSha}`, 'GET'],
  ]);
});

test('signed-commit rejects ambiguous blob creation without another write', async () => {
  const content = Buffer.from('hello\n');
  for (const found of [
    { sha: helloBlobSha, size: content.length, encoding: 'base64', content: 'd3Jvbmc=' },
    { sha: helloBlobSha, size: content.length + 1, encoding: 'base64', content: content.toString('base64') },
    { sha: '0'.repeat(40), size: content.length, encoding: 'base64', content: content.toString('base64') },
  ]) {
    const calls = [];
    const api = async (path, method) => {
      calls.push([path, method ?? 'GET']);
      if (method === 'POST') throw httpError(500);
      return found;
    };
    await assert.rejects(createBlob(api, 'acme/widgets', content), /read-back did not match local bytes/);
    assert.equal(calls.length, 2);
  }
  let lookups = 0;
  await assert.rejects(createBlob(async (_path, method) => {
    if (method === 'POST') throw httpError(500);
    lookups += 1;
    throw httpError(404);
  }, 'acme/widgets', content), /exact SHA read-back failed: HTTP 404/);
  assert.equal(lookups, 1);
  await assert.rejects(createBlob(async (_path, method) => {
    if (method === 'POST') throw httpError(422);
    lookups += 1;
  }, 'acme/widgets', content), /HTTP 422/);
  assert.equal(lookups, 1, 'non-500 errors must not trigger a read-back');
  await assert.rejects(createBlob(async (_path, method) => {
    if (method === 'POST') throw httpError(500);
    throw httpError(500);
  }, 'acme/widgets', content), /exact SHA read-back failed: HTTP 500/);
});

test('signed-commit checks the returned SHA on a successful blob creation', async () => {
  const content = Buffer.from('hello\n');
  const api = async (_path, _method, body) => {
    assert.equal(body.content, content.toString('base64'));
    return { sha: helloBlobSha };
  };
  assert.equal((await createBlob(api, 'acme/widgets', content)).sha, helloBlobSha);
  await assert.rejects(createBlob(async () => ({ sha: '0'.repeat(40) }), 'acme/widgets', content),
    /blob SHA that differs from the local bytes/);
});

// signed-commit belongs to the github-identity add-on; state it explicitly
// so these tests never depend on the caller's own config.
function gateOnEnv(overrides = {}) {
  const config = join(mkdtempSync(join(tmpdir(), 'agent-bot-config-')), 'config.json');
  writeFileSync(config, JSON.stringify({ features: { 'github-identity': true } }));
  return { ...process.env, AGENT_BOT_CONFIG: config, ...overrides };
}

test('parses the stable signed-commit options and rejects malformed input', () => {
  assert.deepEqual(parseSignedCommitArgs([
    '--base', 'main', '--branch', 'feature', '--repo', 'acme/widgets', '--dry-run', '--allow-default-branch',
  ]), {
    base: 'main', branch: 'feature', repo: 'acme/widgets', dryRun: true, allowDefaultBranch: true,
  });
  assert.throws(() => parseSignedCommitArgs(['--base']), /requires a value/);
  assert.throws(() => parseSignedCommitArgs(['--wat']), /unknown option/);
  assert.throws(() => parseSignedCommitArgs(['--repo', 'broken']), /owner\/name/);
});

test('derives repositories only from the configured GitHub host', () => {
  assert.equal(repositoryFromRemote('https://github.com/acme/widgets.git'), 'acme/widgets');
  assert.equal(repositoryFromRemote('git@github.example:acme/widgets.git', 'github.example'), 'acme/widgets');
  assert.throws(() => repositoryFromRemote('https://evil.example/acme/widgets.git'), /pass --repo/);
});

test('the remote lease fails closed on unseen work', () => {
  assert.doesNotThrow(() => assertLease(null, null, 'feature'));
  assert.doesNotThrow(() => assertLease('a'.repeat(40), 'a'.repeat(40), 'feature'));
  assert.throws(() => assertLease('a'.repeat(40), 'b'.repeat(40), 'feature'), /someone else pushed/);
});

test('encodes legal ref characters without losing path structure', () => {
  assert.equal(encodeRefPath('heads/feature#123'), 'heads/feature%23123');
  assert.equal(encodeRefPath('heads/team/topic name'), 'heads/team/topic%20name');
});

test('non-dry publishing refuses to mint when no bot identity is stated', async () => {
  // ENG-0339: a delegate in the owner's account has nothing to sign as. The
  // directory is not consulted; only the absence of --app, GH_AGENT_APP, a
  // pin, or an agent account refuses.
  const cwd = mkdtempSync(join(tmpdir(), 'agent-bot-primary-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '-b', 'feature');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.com');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'core.hooksPath', '/dev/null');
  writeFileSync(join(cwd, 'file.txt'), 'content\n');
  git('add', 'file.txt');
  git('commit', '-m', 'fixture');
  let minted = false;
  await assert.rejects(
    runSignedCommit(parseSignedCommitArgs(['--repo', 'acme/widgets']), {
      cwd,
      env: gateOnEnv({ GH_AGENT_APP: '', AGENT_BOT_ACCOUNT: 'user' }),
      mintImpl: async () => { minted = true; return { token: 'secret' }; },
    }),
    /no bot identity resolves here/,
  );
  assert.equal(minted, false);
});

test('dry-run previews a linear range without minting or network access', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'agent-bot-signed-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.com');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'core.hooksPath', '/dev/null');
  writeFileSync(join(cwd, 'file.txt'), 'base\n');
  git('add', 'file.txt');
  git('commit', '-m', 'base');
  git('remote', 'add', 'origin', 'https://github.com/acme/widgets.git');
  git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  git('switch', '-c', 'feature');
  writeFileSync(join(cwd, 'file.txt'), 'feature\n');
  git('add', 'file.txt');
  git('commit', '-m', 'feature');
  let output = '';
  const result = await runSignedCommit(parseSignedCommitArgs(['--dry-run']), {
    cwd,
    env: gateOnEnv(),
    stdout: { write: (value) => { output += value; } },
    mintImpl: async () => { throw new Error('dry-run minted'); },
    fetchImpl: async () => { throw new Error('dry-run fetched'); },
  });
  assert.equal(result.dryRun, true);
  assert.equal(result.commits.length, 1);
  assert.match(output, /feature/);
  assert.match(output, /dry run — nothing was created or pushed/);
  assert.equal(git('status', '--porcelain'), '');
});

test('dry-run never invokes gpg even when log.showSignature is on (#1257)', async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'agent-bot-signed-'));
  const aux = mkdtempSync(join(tmpdir(), 'agent-bot-gpg-'));
  t.after(() => { rmSync(cwd, { recursive: true, force: true }); rmSync(aux, { recursive: true, force: true }); });
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.com');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'core.hooksPath', '/dev/null');
  writeFileSync(join(cwd, 'file.txt'), 'base\n');
  git('add', 'file.txt');
  git('commit', '-m', 'base');
  const base = git('rev-parse', 'HEAD');
  const tree = git('write-tree');
  // A commit object with a gpgsig header makes `git log` try to run gpg.program
  // when log.showSignature is on — a marker script proves it never ran.
  const marker = join(aux, 'gpg-called');
  const fakeGpg = join(aux, 'fake-gpg.sh');
  writeFileSync(fakeGpg, `#!/bin/sh\ntouch '${marker}'\nexit 0\n`);
  chmodSync(fakeGpg, 0o755);
  const commitObj = `tree ${tree}\nparent ${base}\nauthor T <t@e> 1700000000 +0000\ncommitter T <t@e> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fake\n -----END PGP SIGNATURE-----\n\nfeature\n`;
  const sha = execFileSync('git', ['hash-object', '-t', 'commit', '-w', '--stdin'], { cwd, input: commitObj, encoding: 'utf8' }).trim();
  git('config', 'gpg.program', fakeGpg);
  git('config', 'log.showSignature', 'true');
  git('switch', '-c', 'feature', sha);
  git('remote', 'add', 'origin', 'https://github.com/acme/widgets.git');
  git('update-ref', 'refs/remotes/origin/main', base);
  git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  const result = await runSignedCommit(parseSignedCommitArgs(['--dry-run']), {
    cwd,
    env: gateOnEnv(),
    stdout: { write: () => {} },
    mintImpl: async () => { throw new Error('dry-run minted'); },
    fetchImpl: async () => { throw new Error('dry-run fetched'); },
  });
  assert.equal(result.dryRun, true);
  assert.ok(!existsSync(marker), 'git log must not invoke gpg when reading commit messages');
});

test('replay refuses a commit that credits another soul, before anything is created (ADR-0815)', async () => {
  // A commit made past the hook (--no-verify) still may not credit a soul
  // other than the one bound here; its own soul passes.
  const bound = 'agent_11111111-1111-4111-8111-111111111111';
  const other = 'agent_22222222-2222-4222-8222-222222222222';
  const cwd = mkdtempSync(join(tmpdir(), 'agent-bot-signed-soul-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.com');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'core.hooksPath', '/dev/null');
  writeFileSync(join(cwd, 'file.txt'), 'base\n');
  git('add', 'file.txt');
  git('commit', '-m', 'base');
  git('remote', 'add', 'origin', 'https://github.com/acme/widgets.git');
  git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  git('switch', '-c', 'feature');
  writeFileSync(join(cwd, 'file.txt'), 'own\n');
  git('commit', '-am', `own\n\nCo-authored-by: Bound <${bound}@souls.agent-bot.invalid>\nAgent-Identity: ${bound}`);
  const run = (args) => runSignedCommit(parseSignedCommitArgs(args), {
    cwd,
    env: gateOnEnv({ AGENT_BOT_ID: bound, GH_AGENT_APP: 'acme-codex-agent' }),
    stdout: { write: () => {} },
    mintImpl: async () => { throw new Error('minted'); },
    fetchImpl: async () => { throw new Error('fetched'); },
  });
  assert.equal((await run(['--dry-run'])).commits.length, 1);
  writeFileSync(join(cwd, 'file.txt'), 'other\n');
  git('commit', '-am', `other\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nCo-authored-by: Other <${other}@SOULS.agent-bot.invalid>`);
  await assert.rejects(run(['--dry-run']), new RegExp(`credits another soul as co-author \\(${other}\\).*Nothing was written`));
  // Publishing refuses before a token is minted, so a doomed range causes
  // no owner prompt and no credential receipt.
  await assert.rejects(run([]), /credits another soul/);
});

test('a worktree built on an older commit than its base is refused before anything is minted (#947)', async () => {
  // The feature branch was cut before main gained `added.txt`. Publishing it
  // onto today's main would replay a diff that deletes `added.txt` again.
  const cwd = mkdtempSync(join(tmpdir(), 'agent-bot-signed-stale-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.com');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'core.hooksPath', '/dev/null');
  writeFileSync(join(cwd, 'file.txt'), 'base\n');
  git('add', 'file.txt');
  git('commit', '-m', 'base');
  git('remote', 'add', 'origin', 'https://github.com/acme/widgets.git');
  git('switch', '-c', 'feature');
  writeFileSync(join(cwd, 'file.txt'), 'feature\n');
  git('commit', '-am', 'feature');
  git('switch', 'main');
  writeFileSync(join(cwd, 'added.txt'), 'merged meanwhile\n');
  git('add', 'added.txt');
  git('commit', '-m', 'another PR merged');
  git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  git('switch', 'feature');
  let minted = 0;
  const run = (args) => runSignedCommit(parseSignedCommitArgs(args), {
    cwd,
    env: gateOnEnv({ GH_AGENT_APP: 'acme-codex-agent' }),
    stdout: { write: () => {} },
    mintImpl: async () => { minted += 1; throw new Error('minted'); },
    fetchImpl: async () => { throw new Error('fetched'); },
  });
  const stale = /origin\/main \([0-9a-f]{8}\) is not an ancestor of HEAD.*Rebase first \(git rebase origin\/main\)\. Nothing was written\./;
  await assert.rejects(run(['--base', 'origin/main', '--dry-run']), stale);
  await assert.rejects(run(['--base', 'origin/main']), stale);
  assert.equal(minted, 0);
  // Without --base the merge-base is used, which the worktree is built on.
  assert.equal((await run(['--dry-run'])).commits.length, 1);
  // Once rebased, the same base publishes only the feature's own change.
  git('rebase', '--quiet', 'origin/main');
  let output = '';
  const rebased = await runSignedCommit(parseSignedCommitArgs(['--base', 'origin/main', '--dry-run']), {
    cwd,
    env: gateOnEnv(),
    stdout: { write: (value) => { output += value; } },
    mintImpl: async () => { throw new Error('minted'); },
    fetchImpl: async () => { throw new Error('fetched'); },
  });
  assert.equal(rebased.commits.length, 1);
  assert.match(output, /write 100644 file\.txt/);
  assert.doesNotMatch(output, /added\.txt/);
});
