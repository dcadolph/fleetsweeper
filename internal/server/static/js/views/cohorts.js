// The cohorts page: clusters grouped into populations with their own norms.

import { api } from '../api.js';
import { esc, clusterHref, sevTone } from '../dom.js';
import { renderBar } from '../shell.js';

// renderCohorts shows each cohort, its members, and its within-cohort
// outliers.
export async function renderCohorts() {
  renderBar();
  const data = await api('/cohorts');
  const cohorts = data.cohorts || [];
  let h = "<h2>Cohorts</h2><p class=\"sub\">Clusters grouped into similar populations. Outliers are scored against each cohort's own baseline, not the whole fleet.</p>";
  if (!cohorts.length) return h + '<div class="empty">Fleet too small to subdivide. Outlier detection runs across all clusters.</div>';
  h += '<div class="cohort-grid">';
  cohorts.forEach((c) => {
    const tone = c.source === 'tagged' ? 'ok' : c.source === 'auto' ? 'info' : 'muted';
    h += '<div class="panel"><div class="flex between items-center mb-8">' +
      `<div class="fs-18 fw-600">${esc(c.name)}</div><span class="badge bg-${tone} c-${tone === 'muted' ? 't2' : tone}">${esc(c.source)}</span></div>` +
      `<div class="fs-12 c-t3 mb-8">${c.clusters ? c.clusters.length : 0} clusters</div><div class="flex flex-wrap gap-4 mb-8">` +
      (c.clusters || []).map((cl) => `<a class="pill-link" href="${esc(clusterHref(cl))}">${esc(cl)}</a>`).join('') + '</div>';
    if (c.outliers && c.outliers.length) {
      h += '<div class="top-rule"><div class="fs-12 c-t3 mb-4">Outliers within this cohort</div>' +
        c.outliers.map((o) => `<div class="fs-12"><span class="c-${sevTone(o.severity)} fw-500">${esc(o.cluster)}</span> ` +
          `<span class="c-t3">${esc(o.scanner)}/${esc(o.field)}</span> <span class="mono">${esc(o.value)} vs ${esc(o.fleet_norm)}</span></div>`).join('') + '</div>';
    }
    h += '</div>';
  });
  return h + '</div>';
}
