// Both entry points render the same verified Machine plan. Insert untrusted
// text only through textContent and retain the complete LaunchDaemon content.
export function showFirstHQReview(box, review, settle, setBusy = () => {}) {
  const text = (tag, value) => {
    const node = document.createElement(tag);
    node.textContent = value;
    return node;
  };
  const button = (label, handler) => {
    const node = text('button', label);
    node.type = 'button';
    node.addEventListener('click', handler);
    return node;
  };
  function stepDetails(step) {
    const item = document.createElement('li');
    item.append(text('h3', `${step.action} ${step.target}`), text('p', step.detail));
    const metadata = document.createElement('dl');
    for (const field of ['kind', 'target', 'action', 'owner', 'group', 'mode']) {
      if (Object.hasOwn(step, field)) metadata.append(text('dt', field), text('dd', step[field]));
    }
    item.append(metadata);
    if (step.content) {
      // Machine's service record embeds XML as a JSON string. Show the XML
      // as literal multiline text in addition to the complete digest input.
      let record;
      try { record = JSON.parse(step.content); } catch { /* show exact content below */ }
      if (typeof record?.plist === 'string') {
        item.append(text('h4', 'LaunchDaemon property list'), text('pre', record.plist));
        if (record.service) item.append(text('h4', 'Service release'), text('pre', JSON.stringify(record.service, null, 2)));
        if (record.owner_uid !== undefined) item.append(text('p', 'Service owner UID: ' + record.owner_uid));
      } else item.append(text('h4', 'Content'), text('pre', step.content));
    }
    return item;
  }
  const steps = document.createElement('ol');
  steps.append(...review.plan.steps.map(stepDetails));
  const exact = document.createElement('details');
  exact.append(text('summary', 'Full canonical plan'), text('pre', JSON.stringify(review.plan) + '\n'));
  const controls = document.createElement('div');
  const decide = async (decision) => {
    controls.replaceChildren();
    setBusy(true);
    try {
      const result = await settle(decision);
      if (decision === 'discard') { box.replaceChildren(text('p', 'Review discarded.')); return; }
      const proof = JSON.stringify(result);
      box.replaceChildren(text('p', 'Return this public proof to your administrator.'), text('pre', proof),
        button('Save public proof', () => {
          const url = URL.createObjectURL(new Blob([proof + '\n'], { type: 'application/json' }));
          const link = document.createElement('a');
          link.href = url;
          link.download = 'first-hq-proof.json';
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }));
    } catch (error) { box.replaceChildren(text('p', error.message)); }
    finally { setBusy(false); }
  };
  controls.append(button('Approve with owner presence', () => decide('approve')), button('Discard', () => decide('discard')));
  box.replaceChildren(text('p', 'Compare the Machine fingerprint with the one provided independently by your administrator.'),
    text('pre', `Machine SHA-256: ${review.machine_fingerprint}\nPlan: ${review.plan_id}\nPlan SHA-256: ${review.plan_digest}\nExpires: ${new Date(review.expires_at * 1000).toLocaleString()}`),
    steps, exact, controls);
}
