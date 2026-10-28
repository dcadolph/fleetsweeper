// The outliers page: every distribution the detectors measured, as strips,
// in fleet or cohort scope, then the outlier table and its findings.

import { api } from '../api.js';
import { esc, clusterHref, sevTone, byId, emptyState } from '../dom.js';
import { fixed } from '../format.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { renderStrips } from '../components/strip.js';
import { on } from '../actions.js';

let scope = 'fleet';

// renderOutliers builds the strips for the chosen scope and the outlier
// table for the latest scan.
export async function renderOutliers() {
  renderBar();
  const scans = await api('/scans?limit=1');
  if (!scans || !scans.length) return emptyState('No scans yet, so there is no norm to measure clusters against.');
  const [data, cohorts] = await Promise.all([api('/outliers'), api('/cohorts').catch(() => ({ cohorts: [] }))]);
  const scopes = ['fleet'].concat((cohorts.cohorts || []).filter((c) => c.outliers && c.outliers.length).map((c) => c.name));
  if (!scopes.includes(scope)) scope = 'fleet';
  let h = '<h2>Outlier detection</h2><p class="sub">Each strip is one field across the fleet. The line is the median, the shaded band is the range a value may sit in before it is flagged, red dots sit outside it, and hollow dots sit outside the fleet norm but are held by their cohort.</p>';
  h += '<div class="scope-bar" role="group" aria-label="Norm scope"><span class="eyebrow">Norm</span>' +
    scopes.map((s) => `<button class="btn${s === scope ? ' on' : ''}" data-action="outlier-scope" data-scope="${esc(s)}" aria-pressed="${s === scope}">${esc(s)}</button>`).join('') + '</div>';
  h += `<div id="outlierStrips">${await stripsFor(scope)}</div>`;
  h += '<h3>Outlier table</h3>';
  const all = data.outliers || [];
  const open = all.filter((o) => !o.explained_by);
  const held = all.filter((o) => o.explained_by);
  const head = (first) => `<thead><tr><th scope="col">${first}</th><th scope="col">Cluster</th><th scope="col">Scanner</th><th scope="col">Field</th><th scope="col">Value</th><th scope="col">Fleet norm</th>` +
    '<th scope="col" data-tip="Modified z-score from the median. Exact means the field is flat across the fleet and this cluster is off it.">Deviation</th></tr></thead>';
  const row = (o, first) => `<tr><td${first.cls}>${first.text}</td><td class="fw-500"><a href="${esc(clusterHref(o.cluster))}">${esc(o.cluster)}</a></td>` +
    `<td>${esc(o.scanner)}</td><td>${esc(o.field)}</td><td class="mono">${esc(o.value)}</td><td class="mono">${esc(o.fleet_norm)}</td>` +
    `<td class="mono">${o.exact ? 'exact' : o.deviation ? fixed(o.deviation, 1) : ''}</td></tr>`;
  if (!open.length) {
    h += '<div class="empty">No cluster sits outside every norm that applies to it.</div>';
  } else {
    h += `<div class="tw"><table id="outlierTable">${head('Severity')}<tbody>` +
      open.map((o) => row(o, { cls: ` class="c-${sevTone(o.severity)}"`, text: esc(o.severity) })).join('') + '</tbody></table></div>';
  }
  if (held.length) {
    h += `<details id="outlierHeld" class="mb-12"><summary class="fs-12 c-t2">${held.length} more sit outside the fleet norm but inside their cohort's norm, so they raise no finding.</summary>` +
      `<div class="tw"><table>${head('Held by')}<tbody>` +
      held.map((o) => row(o, { cls: '', text: esc(o.explained_by) })).join('') + '</tbody></table></div></details>';
  }
  if (data.findings && data.findings.length) h += '<h3>Findings from outlier analysis</h3>' + data.findings.map(renderFinding).join('');
  return h;
}

// stripsFor renders the distributions of one scope: fields with outliers
// first, the rest folded away.
async function stripsFor(s) {
  const resp = await api('/distributions?scope=' + encodeURIComponent(s));
  const dists = resp.distributions || [];
  const isOpen = (v) => v.outlier && !v.explained;
  const flagged = dists.filter((d) => d.values.some(isOpen));
  const held = dists.filter((d) => !d.values.some(isOpen) && d.values.some((v) => v.outlier));
  const calm = dists.filter((d) => !d.values.some((v) => v.outlier));
  let h = renderStrips(flagged, { empty: 'No field has a cluster outside the norm in this scope.' });
  if (held.length) h += `<details class="mb-12"><summary class="fs-12 c-t2">${held.length} fields where clusters sit outside the fleet norm but inside their cohort's</summary>${renderStrips(held)}</details>`;
  if (calm.length) h += `<details class="mb-12"><summary class="fs-12 c-t2">${calm.length} more fields where every cluster is inside the norm</summary>${renderStrips(calm)}</details>`;
  return h;
}

on('outlier-scope', async (btn) => {
  scope = btn.dataset.scope;
  document.querySelectorAll('[data-action="outlier-scope"]').forEach((b) => {
    b.classList.toggle('on', b === btn);
    b.setAttribute('aria-pressed', String(b === btn));
  });
  const box = byId('outlierStrips');
  if (box) box.innerHTML = await stripsFor(scope);
});
