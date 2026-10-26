// The cohorts page: the cohort map, then each cohort with its members and
// the strips of the fields where a member sits outside the cohort's norm.

import { api } from '../api.js';
import { esc, clusterHref } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderCohortMap } from '../components/cohort-map.js';
import { renderStrips } from '../components/strip.js';
import { cohortTones } from '../viz.js';

// misplacedFrom maps each cluster with a wrong-cohort finding to the cohort
// it resembles, read from the finding's description.
function misplacedFrom(findings) {
  const out = {};
  (findings || []).filter((f) => f.rule === 'cohort/wrong-cohort').forEach((f) => {
    const m = /clusters with the "([^"]+)" population/.exec(f.description || '');
    out[f.cluster] = m ? m[1] : 'no cohort';
  });
  return out;
}

// renderCohorts builds the map and the per-cohort panels.
export async function renderCohorts() {
  renderBar();
  const [data, mapResp, attr, outliers, scans] = await Promise.all([
    api('/cohorts'), api('/cohorts/map'), api('/score/attribution').catch(() => null), api('/outliers').catch(() => ({ outliers: [] })), api('/scans?limit=1'),
  ]);
  const cohorts = data.cohorts || [];
  let h = "<h2>Cohorts</h2><p class=\"sub\">Clusters grouped into similar populations. Outliers are scored against each cohort's own baseline, not the whole fleet.</p>";
  if (!cohorts.length) return h + '<div class="empty">Fleet too small to subdivide. Outlier detection runs across all clusters.</div>';
  let misplaced = {};
  if (scans && scans.length) {
    const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report').catch(() => null);
    if (rpt) misplaced = misplacedFrom(rpt.findings);
  }
  const costs = (attr && attr.attribution && attr.attribution.by_cluster) || {};
  const points = (mapResp.map && mapResp.map.points) || [];
  const cohortTone = cohortTones(points.map((p) => p.cohort).concat(cohorts.map((c) => c.name)));
  const flagged = new Set((outliers.outliers || []).map((o) => o.cluster));
  cohorts.forEach((c) => (c.outliers || []).forEach((o) => flagged.add(o.cluster)));
  h += '<h3>Cohort map</h3><p class="note mb-8">Clusters close together have similar scanner profiles. Dot size is the score points a cluster costs. Hover a dot for its nearest peers.</p>' +
    renderCohortMap(mapResp.map, costs, flagged, misplaced, cohortTone);
  const stripSets = await Promise.all(cohorts.map((c) => (c.outliers && c.outliers.length
    ? api('/distributions?scope=' + encodeURIComponent(c.name)).then((r) => (r.distributions || []).filter((d) => d.values.some((v) => v.outlier))).catch(() => [])
    : Promise.resolve([]))));
  h += '<h3>Cohorts</h3><div class="cohort-grid">';
  cohorts.forEach((c, i) => {
    const tone = c.source === 'tagged' ? 'ok' : c.source === 'auto' ? 'info' : 'muted';
    h += '<div class="panel"><div class="flex between items-center mb-8">' +
      `<div class="fs-18 fw-600 flex items-center gap-8"><span aria-hidden="true" class="swatch ${cohortTone(c.name)}"></span>${esc(c.name)}</div><span class="badge bg-${tone} c-${tone === 'muted' ? 't2' : tone}">${esc(c.source)}</span></div>` +
      `<div class="fs-12 c-t3 mb-8">${c.clusters ? c.clusters.length : 0} clusters</div><div class="flex flex-wrap gap-4 mb-8">` +
      (c.clusters || []).map((cl) => `<a class="pill-link" href="${esc(clusterHref(cl))}">${esc(cl)}</a>`).join('') + '</div>';
    if (stripSets[i].length) h += '<div class="top-rule"><div class="fs-12 c-t3 mb-4">Fields where a member leaves the cohort norm</div>' + renderStrips(stripSets[i]) + '</div>';
    h += '</div>';
  });
  return h + '</div>';
}
