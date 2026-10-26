// The what-if panel: for a finding raised by the norm, projects the fleet with
// the cluster's value fixed to the norm, from POST /api/whatif. It shows the
// score before and after, how the norm itself moves, the field's strip before
// and after, and which clusters would newly flag. Nothing is written.

import { esc } from '../dom.js';
import { fmt } from '../viz.js';
import { send } from '../auth.js';
import { openDrawer } from './drawer.js';
import { renderStrip } from './strip.js';

// FIX_LABELS describes each fix kind the server applies.
const FIX_LABELS = {
  median: 'set to the median',
  mode: 'set to the most common value',
  consensus: 'given the consensus members',
  remove: 'removed from the fleet',
};

// normShift describes how the norm moves for a numeric field, or the norm itself otherwise.
function normShift(o) {
  if (o.before.kind === 'numeric') {
    const m = o.after ? `median ${fmt(o.before.median)} to ${fmt(o.after.median)}` : `median ${fmt(o.before.median)}`;
    const mad = o.after ? `, spread ${fmt(o.before.mad)} to ${fmt(o.after.mad)}` : '';
    return m + mad;
  }
  if (o.before.kind === 'string') return `most common value ${o.before.mode}`;
  return `${(o.before.consensus || []).length} consensus members`;
}

// outcomeHTML renders a what-if outcome for cluster.
export function outcomeHTML(o, cluster) {
  const d = o.score_after - o.score_before;
  const tone = d > 0 ? 'ok' : d < 0 ? 'crit' : 't2';
  let h = '<div class="whatif-score">' +
    `<div><div class="eyebrow">Fleet score now</div><div class="meter-value">${o.score_before}</div></div>` +
    `<div><div class="eyebrow">If fixed</div><div class="meter-value c-${tone}">${o.score_after}</div></div>` +
    `<div><div class="eyebrow">Change</div><div class="meter-value c-${tone}">${d > 0 ? '+' : ''}${d}</div></div></div>`;
  h += `<p class="note mb-8">${esc(cluster)} ${esc(FIX_LABELS[o.fix.kind] || o.fix.kind)} of the ${esc(o.fix.scope === 'fleet' ? 'fleet' : 'cohort ' + o.fix.scope)}. Norm: ${esc(normShift(o))}.</p>`;
  h += '<div class="eyebrow">Before</div>' + renderStrip(o.before, cluster);
  h += '<div class="eyebrow mt-8">After</div>' +
    (o.after ? renderStrip(o.after, cluster) : '<p class="note">Every cluster agrees after the fix, so there is no spread left to draw.</p>');
  if (o.new_outliers && o.new_outliers.length) {
    h += `<p class="c-warn fs-12 mt-8">Would newly flag: ${o.new_outliers.map(esc).join(', ')}. Moving the norm moves its band.</p>`;
  }
  if (o.cleared_outliers && o.cleared_outliers.length) {
    h += `<p class="c-ok fs-12">Would clear: ${o.cleared_outliers.map(esc).join(', ')}.</p>`;
  }
  return h + '<p class="note mt-8">Nothing was changed. This is a projection from the scan as stored.</p>';
}

// openWhatIf opens the panel for the finding card el and fills it when the projection returns.
export async function openWhatIf(el) {
  const cluster = el.dataset.cluster;
  const panel = openDrawer({
    title: 'What if it matched the norm',
    body: `<p class="fs-14 fw-600 mb-4">${esc(el.dataset.title)}</p><div class="whatif-body"><p class="note">Projecting...</p></div>`,
    actions: [],
  });
  const body = { cluster, scanner: el.dataset.scanner, field: el.dataset.field, scope: el.dataset.scope || undefined };
  const r = await send('POST', '/whatif', body, 'Projection');
  const box = panel.querySelector('.whatif-body');
  if (!box || !panel.isConnected) return;
  if (!r) {
    box.innerHTML = '<p class="note">The projection could not run. The reason is in the notice.</p>';
    return;
  }
  const out = await r.json();
  box.innerHTML = outcomeHTML(out.outcome, cluster);
}
