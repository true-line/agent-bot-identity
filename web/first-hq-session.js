import { showFirstHQReview } from './first-hq.js';

const box = document.getElementById('review');
const launch = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
let credential = launch;
let active = true;
const post = (verb, body, keepalive = false) => fetch('./' + verb, {
  method: 'POST', credentials: 'omit', cache: 'no-store', keepalive,
  headers: { authorization: 'Bearer ' + credential, 'content-type': 'application/json' },
  body: JSON.stringify(body),
});
window.addEventListener('pagehide', () => {
  if (active) post('close', {}, true).catch(() => {});
  active = false;
  credential = '';
}, { once: true });
async function readResponse(verb, body) {
  const response = await post(verb, body);
  if (response.status === 503) throw new Error('The signed Machine owner helper or its protected credential is unavailable. Keep the existing owner pin.');
  if (!response.ok) throw new Error('The review was refused, closed or expired. No proof was returned.');
  return response.json();
}
try {
  const { session, review } = await readResponse('claim', {});
  credential = session;
  showFirstHQReview(box, review, async (decision) => {
    try { return await readResponse(decision, { plan_digest: review.plan_digest }); }
    finally { active = false; credential = ''; }
  });
} catch (error) { box.textContent = error.message; }
