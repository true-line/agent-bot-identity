// Integrity checks reproduce the genuine published v0.5.0 dependency; the
// runtime pin stays authoritative when locating its offline data directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, chmodSync, rmSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyHqContractTree } from '../identity/hq-member-contracts.mjs';
import { pinnedComponent } from './helpers/pinned-hq-components.mjs';
const pin = Object.freeze(JSON.parse(readFileSync(new URL('../identity/hq-member-contracts.json', import.meta.url))).release);

test('real published manifest is reproduced, while changed bytes/mode/extra files and symlinks refuse', () => {
  const source = pinnedComponent('soul-contracts', pin.commit);
  assert.equal(verifyHqContractTree(source, pin).size, pin.files);
  for (const mutation of ['bytes', 'mode', 'extra', 'symlink', 'root-symlink']) {
    const root = mkdtempSync(join(tmpdir(), 'hq-contract-')); const copy = join(root, 'tree');
    try {
      for (const path of pin.paths) cpSync(join(source, path), join(copy, path), { recursive: true });
      const file = join(copy, 'schemas/hq/v1/hello.schema.json');
      if (mutation === 'bytes') writeFileSync(file, Buffer.concat([readFileSync(file), Buffer.from('\n')]));
      if (mutation === 'mode') chmodSync(file, 0o755);
      if (mutation === 'extra') writeFileSync(join(copy, 'schemas/extra.json'), '{}');
      if (mutation === 'symlink') { rmSync(file); symlinkSync(join(source, 'schemas/hq/v1/hello.schema.json'), file); }
      let directory = copy;
      if (mutation === 'root-symlink') { directory = join(root, 'link'); symlinkSync(copy, directory); }
      assert.throws(() => verifyHqContractTree(directory, pin), { code: 'inbox-contracts-unavailable' }, mutation);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});
