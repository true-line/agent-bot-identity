// Identity-owned composition over the public SDK. No bind implementation,
// legacy daemon client or upstream notice client belongs on this path.
import { REGISTRY_CODES, HOST_CODES } from './vendor/agent-bot-sdk/errors.mjs';
import { connectMemberQueries } from './vendor/agent-bot-sdk/member-client.mjs';
import { createHqInboxClient } from './hq-inbox-client.mjs';
import { loadHqMemberContracts } from './hq-member-contracts.mjs';

const SAFE_CODES = new Set([...Object.keys(REGISTRY_CODES), ...HOST_CODES, 'transport', 'souls.unknown_member', 'inbox-no-live-runtime', 'inbox-bad-request', 'inbox-invalid-response', 'frame_too_large']);
const FIELDS = ['AGENT_BOT_SOULS_SOCKET', 'AGENT_BOT_SOULS_MEMBER_TOKEN', 'AGENT_BOT_SOULS_BROKER'];
const fail = (code, text) => { throw Object.assign(new Error(`${text} [${code}]`), { code }); };
export const hasHqMemberEnvironment = (env) => FIELDS.some((name) => Object.hasOwn(env, name));

export function createHqInboxBackend({ env = process.env } = {}) {
  const input = Object.fromEntries(FIELDS.map((name) => [name, env[name]]));
  // The optional broker endpoint follows the existing Soul default semantics.
  if (input.AGENT_BOT_SOULS_BROKER === '') input.AGENT_BOT_SOULS_BROKER = undefined;
  const controller = new AbortController();
  let pending; let connection; let inbox; let closed = false; let closing;
  const open = () => { if (closed) fail('inbox-unavailable', 'HQ inbox member client is closed'); };
  const ready = () => {
    open();
    if (!pending) pending = (async () => {
      if (typeof input.AGENT_BOT_SOULS_SOCKET !== 'string' || !input.AGENT_BOT_SOULS_SOCKET
        || typeof input.AGENT_BOT_SOULS_MEMBER_TOKEN !== 'string' || !input.AGENT_BOT_SOULS_MEMBER_TOKEN
        || (input.AGENT_BOT_SOULS_BROKER !== undefined && (typeof input.AGENT_BOT_SOULS_BROKER !== 'string' || !input.AGENT_BOT_SOULS_BROKER))) {
        fail('inbox-no-live-runtime', 'HQ inbox requires the complete inherited Soul member environment');
      }
      // No socket or legacy effect happens before the real release gate.
      const contracts = loadHqMemberContracts({ env });
      connection = await connectMemberQueries({ memberSocket: input.AGENT_BOT_SOULS_SOCKET, memberToken: input.AGENT_BOT_SOULS_MEMBER_TOKEN, signal: controller.signal,
        ...(input.AGENT_BOT_SOULS_BROKER ? { brokerSocket: input.AGENT_BOT_SOULS_BROKER } : {}), contracts });
      if (closed) { await connection.close(); open(); }
      inbox = createHqInboxClient({ queries: connection.queries, ...contracts });
      return inbox;
    })().catch(async (error) => {
      if (connection) await connection.close().catch(() => {});
      // Never reflect transport errors that may contain private socket paths.
      if (['inbox-no-live-runtime', 'inbox-contracts-unavailable', 'inbox-unavailable'].includes(error?.code)) throw error;
      fail(SAFE_CODES.has(error?.code) ? error.code : 'inbox-unavailable', 'HQ inbox member bootstrap failed');
    });
    return pending;
  };
  return Object.freeze({
    async takeInbox() {
      const client = await ready(); open();
      try { return await client.takeInbox(); }
      catch (error) { fail(SAFE_CODES.has(error?.code) ? error.code : 'inbox-unavailable', 'HQ inbox request failed or its result could not be accepted'); }
    },
    close() {
      if (closing) return closing;
      closed = true; controller.abort();
      closing = connection ? Promise.resolve(connection.close()) : Promise.resolve();
      // A bootstrap that finishes after shutdown cannot publish a live client.
      pending?.catch(() => {});
      return closing;
    },
  });
}
