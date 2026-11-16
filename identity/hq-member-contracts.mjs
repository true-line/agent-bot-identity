// Offline member dependency boundary. A directory is data, never authority:
// every file/mode must match the reviewed immutable release manifest.
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonicalDigest, canonicalBytes } from './vendor/agent-bot-sdk/wire/canonical-json.mjs';
import { parseStrict } from './vendor/agent-bot-sdk/wire/strict-json.mjs';
import { validate } from './vendor/agent-bot-sdk/wire/schema.mjs';
import { negotiateVersions } from './vendor/agent-bot-sdk/wire/versions.mjs';

const CONFIG = new URL('./hq-member-contracts.json', import.meta.url);
const PATHS = ['errors', 'fixtures', 'schemas'];
const unavailable = () => Object.assign(new Error('HQ inbox requires its pinned soul-contracts v0.5.0 verified offline dependency [inbox-contracts-unavailable]'), { code: 'inbox-contracts-unavailable' });
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function verifyHqContractTree(directory, pin) {
  if (!object(pin) || Object.keys(pin).some((k) => !['repository', 'tag', 'commit', 'paths', 'digest_algorithm', 'digest', 'files'].includes(k))
    || pin.repository !== 'https://github.com/true-line/soul-contracts.git' || !/^v\d+\.\d+\.\d+$(?![\s\S])/.test(pin.tag ?? '')
    || !/^[0-9a-f]{40}$(?![\s\S])/.test(pin.commit ?? '') || pin.digest_algorithm !== 'sha256-manifest-v1'
    || !/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(pin.digest ?? '') || !Number.isSafeInteger(pin.files) || pin.files < 1 || pin.files > 10000
    || JSON.stringify(pin.paths) !== JSON.stringify(PATHS)) throw unavailable();
  const entries = new Map(); let bytesTotal = 0;
  const walk = (rel) => {
    const path = join(directory, rel); const stat = lstatSync(path);
    if (stat.isDirectory()) { for (const child of readdirSync(path).sort()) walk(`${rel}/${child}`); return; }
    if (!stat.isFile() || stat.size > 32 * 1024 * 1024 || entries.size >= pin.files) throw unavailable();
    const bytes = readFileSync(path); bytesTotal += bytes.length;
    if (bytesTotal > 32 * 1024 * 1024) throw unavailable();
    entries.set(rel, { bytes, mode: stat.mode & 0o111 ? '100755' : '100644' });
  };
  try {
    if (!lstatSync(directory).isDirectory()) throw unavailable();
    for (const path of PATHS) walk(path);
    const manifest = Object.fromEntries([...entries].map(([path, { bytes, mode }]) => [path, {
      sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length, mode,
    }]));
    if (entries.size !== pin.files || canonicalDigest(manifest) !== pin.digest) throw unavailable();
    return entries;
  } catch { throw unavailable(); }
}

export function loadHqMemberContracts({ env = process.env } = {}) {
  let declaration;
  try { declaration = parseStrict(readFileSync(CONFIG)); } catch { throw unavailable(); }
  if (!object(declaration) || Object.keys(declaration).sort().join(',') !== 'release,required_tag,schema_version'
    || declaration.schema_version !== 1 || declaration.required_tag !== 'v0.5.0' || !declaration.release
    || declaration.release.tag !== declaration.required_tag) throw unavailable();
  const pin = declaration.release;
  const directory = env.AGENT_BOT_SOUL_CONTRACTS || fileURLToPath(new URL(`../node_modules/.cache/soul-contracts-${pin.commit}/`, import.meta.url));
  const entries = verifyHqContractTree(directory, pin);
  const schemas = new Map();
  try {
    for (const [path, { bytes }] of entries) if (path.startsWith('schemas/') && path.endsWith('.schema.json')) schemas.set(path.slice(8), parseStrict(bytes));
    for (const path of ['hq/v1/notice-query.schema.json', 'hq/v1/notice-result.schema.json', 'hq/v1/admission-result.schema.json', 'common/v1/error-response.schema.json']) if (!schemas.has(path)) throw unavailable();
  } catch { throw unavailable(); }
  const errors = (path, value) => {
    const schema = schemas.get(path); if (!schema) throw unavailable();
    return validate(schema, value);
  };
  const record = (path, value) => {
    if (errors(path, value).length) throw Object.assign(new Error('invalid HQ member contract record'), { code: 'inbox-invalid-response' });
    return value;
  };
  return Object.freeze({
    directory, canonicalBytes,
    validateQuery: (value) => errors('hq/v1/notice-query.schema.json', value),
    validateResult: (value) => errors('hq/v1/notice-result.schema.json', value),
    record,
    admission(result, hello) {
      record('hq/v1/admission-result.schema.json', result);
      if (result.request_id !== hello.request_id) throw Object.assign(new Error('HQ admission correlation differs'), { code: 'inbox-invalid-response' });
      for (const [name, version] of Object.entries(result.negotiated_versions)) {
        negotiateVersions({ [name]: [version] }, { [name]: ['hq', 'wire', 'task'].includes(name) ? [1] : [] }, { required: [name] });
        if (!hello.supported_versions[name]?.includes(version)) throw Object.assign(new Error('HQ selected an unoffered contract version'), { code: 'unsupported_version' });
      }
      return result;
    },
  });
}
