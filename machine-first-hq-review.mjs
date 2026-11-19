// One transferred plan, one direct browser, one purpose-specific native
// signature. No daemon, permanent token, principal store, or general UI API.
import { execFile } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import { approveFirstHQ } from './identity-host.mjs';
import { reviewFirstHQ, verifiedFirstHQProof } from './machine-first-hq.mjs';

const assets = new Map([
  ['/first-hq/', ['first-hq.html', 'text/html; charset=utf-8']],
  ['/first-hq/first-hq-session.js', ['first-hq-session.js', 'text/javascript']],
  ['/first-hq/first-hq.js', ['first-hq.js', 'text/javascript']],
  ['/first-hq/style.css', ['style.css', 'text/css']],
]);
const headers = {
  'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
};

function token() { return randomBytes(32).toString('base64url'); }
function matches(value, expected) {
  if (typeof value !== 'string' || !expected) return false;
  const a = Buffer.from(value);
  const b = Buffer.from('Bearer ' + expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readChallenge(file) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const limit = 64 * 1024;
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > limit) throw new Error('Expected a regular challenge file of at most 64 KiB.');
    const bytes = Buffer.alloc(limit + 1);
    let size = 0;
    while (size <= limit) {
      const read = readSync(fd, bytes, size, bytes.length - size, null);
      if (!read) break;
      size += read;
    }
    if (size > limit) throw new Error('The challenge exceeds 64 KiB.');
    return JSON.parse(bytes.subarray(0, size).toString('utf8'));
  } finally { closeSync(fd); }
}

export async function openFirstHQReview(file, {
  env, home, platform = process.platform, now = () => Math.floor(Date.now() / 1000),
  signer = approveFirstHQ, openBrowser = (url) => promisify(execFile)('/usr/bin/open', [url]),
} = {}) {
  if (platform !== 'darwin') throw new Error('First-HQ provisioning requires macOS.');
  const challenge = readChallenge(file);
  const review = reviewFirstHQ(challenge, now());
  const launch = token();
  let session;
  let claimed = false;
  let signing = false;
  let closed = false;
  let resolveFinished;
  let rejectFinished;
  let timer;
  let origin;
  const finished = new Promise((resolve, reject) => { resolveFinished = resolve; rejectFinished = reject; });
  const cancel = new AbortController();
  function finish(outcome, error) {
    if (closed) return;
    closed = true;
    session = undefined;
    cancel.abort();
    clearTimeout(timer);
    server.close();
    server.closeAllConnections();
    if (error) rejectFinished(error);
    else resolveFinished(outcome);
  }
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, async (req, res) => {
    function reply(status, payload, type = 'application/json') {
      res.writeHead(status, { ...headers, 'content-type': type });
      res.end(type === 'application/json' ? JSON.stringify(payload) : payload);
    }
    try {
      if (closed || req.socket.remoteAddress !== '127.0.0.1' || 'http://' + req.headers.host !== origin
        || Object.keys(req.headers).some((h) => h === 'forwarded' || h.startsWith('x-forwarded-'))) return reply(403, {});
      const asset = assets.get(req.url);
      if (req.method === 'GET' && asset) return reply(200, readFileSync(new URL('./web/' + asset[0], import.meta.url)), asset[1]);
      if (req.method !== 'POST' || !['claim','approve','discard','close'].some((v) => req.url === '/first-hq/' + v)) return reply(404, {});
      if (req.headers.origin !== origin || req.headers['content-type'] !== 'application/json') return reply(403, {});
      const claim = req.url.endsWith('/claim');
      const close = req.url.endsWith('/close');
      const presented = req.headers.authorization;
      if (!(claim ? !claimed && matches(presented, launch) : matches(presented, session) || (close && matches(presented, launch)))) return reply(403, {});
      let raw = '';
      for await (const chunk of req) {
        if (Buffer.byteLength(raw) + chunk.length > 256) return reply(413, {});
        raw += chunk.toString();
      }
      const body = JSON.parse(raw);
      if (!body || typeof body !== 'object' || Array.isArray(body)) return reply(400, {});
      // Recheck after reading the body: another request may have claimed,
      // closed or consumed the session while this request was in flight.
      if (closed || cancel.signal.aborted || (claim && claimed)) return reply(409, {});
      if (claim) {
        if (Object.keys(body).length) return reply(400, {});
        claimed = true;
        session = token();
        return reply(200, { session, review });
      }
      const discard = req.url.endsWith('/discard');
      if (close ? Object.keys(body).length !== 0
        : Object.keys(body).length !== 1 || body.plan_digest !== challenge.plan_digest) return reply(409, {});
      if (close || discard) {
        // Revoke even when a presence prompt is outstanding.
        session = undefined;
        cancel.abort();
        res.once('finish', () => finish('discarded'));
        return reply(200, { discarded: true });
      }
      if (signing) return reply(409, {});
      signing = true;
      res.once('close', () => { if (!res.writableEnded) finish('discarded'); });
      try {
        reviewFirstHQ(challenge, now());
        const output = await signer(challenge, { env, home, platform, signal: cancel.signal });
        if (closed || cancel.signal.aborted) return;
        reviewFirstHQ(challenge, now());
        const proof = verifiedFirstHQProof(challenge, output);
        res.once('finish', () => finish('approved'));
        reply(200, proof);
      } catch {
        if (closed) return;
        res.once('finish', () => finish('refused'));
        reply(409, {});
      }
    } catch { if (!res.headersSent && !closed) reply(400, {}); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = 'http://127.0.0.1:' + server.address().port;
  timer = setTimeout(() => finish('expired'), Math.max(0, challenge.expires_at - now()) * 1000);
  // The fragment is never sent to the server and is immediately removed
  // from browser history. It is never written to stdout, stderr or disk.
  Promise.resolve().then(() => openBrowser(origin + '/first-hq/#' + launch))
    .catch(() => finish(null, new Error('Could not open the local first-HQ review.')));
  return finished;
}
