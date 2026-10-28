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
  let h = '<h2>Outlier detection</h2><p class="sub">Each strip is one field across the fleet. The line is the median, the shaded band is the range a value may sit in before it is flagged, and red dots sit outside it.</p>';
  h += '<div class="scope-bar" role="group" aria-label="Norm scope"><span class="eyebrow">Norm</span>' +
    scopes.map((s) => `<button class="btn${s === scope ? ' on' : ''}" data-action="outlier-scope" data-scope="${esc(s)}" aria-pressed="${s === scope}">${esc(s)}</button>`).join('') + '</div>';
  h += `<div id="outlierStrips">${await stripsFor(scope)}</div>`;
  h += '<h3>Outlier table</h3>';
  if (!data.outliers || !data.outliers.length) {
    h += '<div class="empty">No outliers detected. Fleet is consistent.</div>';
  } else {
    h += '<div class="tw"><table><thead><tr><th scope="col">Severity</th><th scope="col">Cluster</th><th scope="col">Scanner</th><th scope="col">Field</th><th scope="col">Value</th><th scope="col">Fleet norm</th>' +
      '<th scope="col" data-tip="Modified z-score from the median. Exact means the field is flat across the fleet and this cluster is off it.">Deviation</th></tr></thead><tbody>';
    data.outliers.forEach((o) => {
      h += `<tr><td class="c-${sevTone(o.severity)}">${esc(o.severity)}</td><td class="fw-500"><a href="${esc(clusterHref(o.cluster))}">${esc(o.cluster)}</a></td>` +
        `<td>${esc(o.scanner)}</td><td>${esc(o.field)}</td><td class="mono">${esc(o.value)}</td><td class="mono">${esc(o.fleet_norm)}</td>` +
        `<td class="mono">${o.exact ? 'exact' : o.deviation ? fixed(o.deviation, 1) : ''}</td></tr>`;
    });
    h += '</tbody></table></div>';
  }
  if (data.findings && data.findings.length) h += '<h3>Findings from outlier analysis</h3>' + data.findings.map(renderFinding).join('');
  return h;
}

// stripsFor renders the distributions of one scope: fields with outliers
// first, the rest folded away.
async function stripsFor(s) {
  const resp = await api('/distributions?scope=' + encodeURIComponent(s));
  const dists = resp.distributions || [];
  const flagged = dists.filter((d) => d.values.some((v) => v.outlier));
  const calm = dists.filter((d) => !d.values.some((v) => v.outlier));
  let h = renderStrips(flagged, { empty: 'No field has a cluster outside the norm in this scope.' });
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
