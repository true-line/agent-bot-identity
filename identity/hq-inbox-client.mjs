// Member-side compatibility preparation for PDR-0062. The integration host
// supplies an already-bound broker request, current freshness and the shared
// SDK's validators/canonicalizer. This module discovers no socket, credential,
// binding, queue or scope, and is not wired into the legacy MCP path yet.
import { randomUUID } from 'node:crypto';

const CONTENT_FIELDS = ['repo', 'app', 'event', 'action', 'kind', 'title', 'actor', 'url', 'text', 'type', 'number', 'createdAt'];
const SOURCE_BYTES = 65_536;
const RESULT_BYTES = 524_288;
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

async function validated(check, value, code) {
  // Match the shared SDK validator's error-array interface. An absent or
  // permissive boolean/undefined verdict is not a validation result.
  let errors;
  try { errors = await check(value); } catch { fail(code, 'HQ notice contract validation failed'); }
  if (!Array.isArray(errors) || errors.length !== 0) fail(code, 'HQ notice contract validation failed');
}

// request(kind, payload) MUST send consume-one at most once. It must not be a
// generic read helper that reconnects and replays after an unknown outcome.
// Validators come from verified shared contracts, not local schema copies.
export function createHqInboxClient({ request, currentRuntime, validateQuery, validateResult, canonicalBytes, requestId = randomUUID } = {}) {
  for (const dependency of [request, currentRuntime, validateQuery, validateResult, canonicalBytes, requestId]) {
    if (typeof dependency !== 'function') throw new TypeError('HQ inbox client requires bound transport, freshness and shared validation');
  }

  return Object.freeze({
    async takeInbox(...args) {
      if (args.length !== 0) fail('inbox-bad-request', 'HQ inbox consume-one takes no caller selectors');
      const runtime = await currentRuntime();
      if (!object(runtime) || Object.keys(runtime).length !== 2
        || !Object.keys(runtime).every((key) => ['installation_epoch', 'lease_generation'].includes(key))
        || !Number.isSafeInteger(runtime.installation_epoch) || runtime.installation_epoch < 1
        || !Number.isSafeInteger(runtime.lease_generation) || runtime.lease_generation < 1) {
        fail('inbox-no-live-runtime', 'HQ inbox requires current bound runtime freshness');
      }
      const query = freeze({ contract: 'hq/v1', request_id: requestId(), operation: 'consume-one',
        required_capabilities: ['notices-v1'], installation_epoch: runtime.installation_epoch,
        lease_generation: runtime.lease_generation });
      await validated(validateQuery, query, 'inbox-bad-request');

      // Exactly one transport invocation; propagate refusals and unknown
      // outcomes unchanged. There is no upstream client or retry path here.
      const received = await request('notices.consume-one', query);
      let result;
      try { result = freeze(structuredClone(received)); } catch { fail('inbox-invalid-response', 'HQ returned an invalid notice result'); }
      if (!object(result)) fail('inbox-invalid-response', 'HQ returned an invalid notice result');
      if (result.contract !== 'hq/v1') fail('unsupported_version', 'HQ notice result contract is unsupported');
      if (!Array.isArray(result.required_capabilities) || result.required_capabilities.length !== 1
        || result.required_capabilities[0] !== 'notices-v1') fail('required_capability_missing', 'HQ notice result capability requirement is unsupported');
      await validated(validateResult, result, 'inbox-invalid-response');
      if (result.request_id !== query.request_id || result.operation !== query.operation) {
        fail('inbox-invalid-response', 'HQ notice result correlation or operation differs');
      }
      if (!Array.isArray(result.notices) || result.notices.length > 1) {
        fail('inbox-invalid-response', 'HQ consume-one returned an invalid notice count');
      }
      let oversized;
      try {
        const length = (value) => {
          const bytes = canonicalBytes(value);
          if (!(bytes instanceof Uint8Array)) throw new TypeError('canonical bytes required');
          return bytes.byteLength;
        };
        oversized = length(result) > RESULT_BYTES
          || result.notices.some((notice) => length({ id: notice.message_id, ...notice.content }) > SOURCE_BYTES);
      } catch { fail('inbox-invalid-response', 'HQ notice result has no canonical JSON encoding'); }
      if (oversized) fail('frame_too_large', 'HQ notice result exceeds the shared byte budget');
      if (result.notices.length === 0) return { event: null };
      const notice = result.notices[0];
      // The schema is closed; the projection also makes the legacy surface's
      // output boundary explicit. No provenance, leases or custody internals.
      const content = Object.fromEntries(CONTENT_FIELDS.filter((key) => Object.hasOwn(notice.content, key)).map((key) => [key, notice.content[key]]));
      return { event: { id: notice.message_id, ...content, pulled: true } };
    },
  });
}
