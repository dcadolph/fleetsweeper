// The cohort map: every cluster placed by classical scaling of its cohort
// features, cohorts outlined by their convex hulls, dots sized by the score
// points the cluster costs, and outliers ringed.

import { esc, clusterHref } from '../dom.js';
import { linear, hull, cohortTones, fmt } from '../viz.js';

const W = 640;
const H = 420;
const PAD = 28;

// renderCohortMap returns the map SVG and a cohort legend. costs maps a
// cluster to its score cost, outliers is a Set of flagged clusters, and
// misplaced maps a cluster to the cohort it resembles more. tone names a
// cohort's color class and defaults to one built from the map's cohorts.
export function renderCohortMap(map, costs, outliers, misplaced, tone) {
  const pts = (map && map.points) || [];
  if (pts.length < 2) return '<div class="empty">Not enough clusters to map.</div>';
  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const span = Math.max(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys)) || 1;
  const cx = (Math.max(...xs) + Math.min(...xs)) / 2;
  const cy = (Math.max(...ys) + Math.min(...ys)) / 2;
  const sx = linear(cx - span / 2, cx + span / 2, PAD, W - PAD);
  const sy = linear(cy - span / 2, cy + span / 2, H - PAD, PAD);
  const placed = pts.map((p) => ({ ...p, px: sx(p.x), py: sy(p.y) }));
  const cohorts = [...new Set(placed.map((p) => p.cohort))].sort();
  const cohortTone = tone || cohortTones(cohorts);
  let svg = `<svg class="cmap" viewBox="0 0 ${W} ${H}" role="img" aria-label="Cohort map of ${placed.length} clusters">`;
  cohorts.forEach((c) => {
    const members = placed.filter((p) => p.cohort === c).map((p) => ({ x: p.px, y: p.py }));
    const shape = hull(members);
    if (shape.length >= 3) {
      svg += `<polygon class="hull ${cohortTone(c)}" points="${shape.map((p) => p.x.toFixed(1) + ',' + p.y.toFixed(1)).join(' ')}"/>`;
    } else if (shape.length === 2) {
      svg += `<line class="hull-line ${cohortTone(c)}" x1="${shape[0].x.toFixed(1)}" y1="${shape[0].y.toFixed(1)}" x2="${shape[1].x.toFixed(1)}" y2="${shape[1].y.toFixed(1)}"/>`;
    }
  });
  const maxCost = Math.max(1, ...placed.map((p) => costs[p.cluster] || 0));
  placed.forEach((p) => {
    const r = 4 + 8 * Math.sqrt((costs[p.cluster] || 0) / maxCost);
    const peers = (p.peers || []).slice(0, 3).map((x) => x.cluster + ' ' + fmt(x.distance)).join(', ');
    const tipText = `${p.cluster} · ${p.cohort}${costs[p.cluster] ? ' · costs ' + fmt(costs[p.cluster]) + ' points' : ''}${misplaced[p.cluster] ? ' · resembles ' + misplaced[p.cluster] : ''}${peers ? ' · nearest: ' + peers : ''}`;
    svg += `<a href="${esc(clusterHref(p.cluster))}" data-tip="${esc(tipText)}" aria-label="${esc(tipText)}">` +
      `<circle class="pt ${cohortTone(p.cohort)}${outliers.has(p.cluster) ? ' out' : ''}${misplaced[p.cluster] ? ' misplaced' : ''}" cx="${p.px.toFixed(1)}" cy="${p.py.toFixed(1)}" r="${r.toFixed(1)}"/></a>`;
  });
  svg += '</svg>';
  const legend = '<div class="legend">' + cohorts.map((c) => `<span><span class="swatch ${cohortTone(c)}"></span> ${esc(c)}</span>`).join('') +
    '<span><span class="swatch ring-swatch"></span> has an outlier</span><span><span class="swatch dashed-swatch"></span> may be in the wrong cohort</span>' +
    `<span class="ml-auto">stress ${esc(fmt(map.stress))}${map.stress > 0.2 ? ', a rough picture' : ''}</span></div>`;
  return svg + legend;
}
