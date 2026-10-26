// The trends page: small multiples of the most deviant fields over recent
// scans, each with the fleet median, its band, and the clusters outside it,
// then the trend findings and the direction table.

import { api } from '../api.js';
import { esc, token } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { makeChart } from '../charts.js';
import { fieldLabel } from '../viz.js';

const MULTIPLES = 6;
const SCANS = 24;

// renderTrends builds the small multiples and the trend tables.
export async function renderTrends() {
  renderBar();
  const [dists, data] = await Promise.all([api('/distributions'), api('/trends?scans=20')]);
  const fields = (dists.distributions || []).filter((d) => d.kind === 'numeric' && d.mad > 0).slice(0, MULTIPLES);
  const histories = await Promise.all(fields.map((d) =>
    api(`/distributions/history?scanner=${encodeURIComponent(d.scanner)}&field=${encodeURIComponent(d.field)}&scans=${SCANS}`).catch(() => null)));
  let h = '<h2>Fleet trends</h2><p class="sub">The fields furthest from the norm, over recent scans: the fleet median, the band around it, and every cluster that ends outside it.</p>';
  h += fields.length
    ? '<div class="multiples">' + fields.map((d, i) => `<div class="chc"><h4>${esc(fieldLabel(d))}</h4><div class="chart-180"><canvas id="mult-${i}"></canvas></div></div>`).join('') + '</div>'
    : '<div class="empty">No numeric field varies across the fleet yet.</div>';
  if (data.message) {
    h += `<p class="note mt-12">${esc(data.message)}</p>`;
  } else {
    if (data.findings && data.findings.length) h += '<h3>Trend findings</h3>' + data.findings.map(renderFinding).join('');
    if (data.fleet_trends && data.fleet_trends.length) {
      h += '<h3>Fleet drift over time</h3><div class="tw"><table><thead><tr><th scope="col">Scanner</th><th scope="col">Field</th><th scope="col">Direction</th><th scope="col">Points</th><th scope="col">First value</th><th scope="col">Last value</th></tr></thead><tbody>';
      data.fleet_trends.forEach((t) => {
        const tone = t.direction === 'worsening' ? 'crit' : t.direction === 'improving' ? 'ok' : 't2';
        const pts = t.points || [];
        h += `<tr><td>${esc(t.scanner)}</td><td>${esc(t.field)}</td><td class="c-${tone} fw-600">${esc(t.direction)}</td><td>${pts.length}</td>` +
          `<td class="mono">${esc(pts.length ? pts[0].value : '-')}</td><td class="mono">${esc(pts.length ? pts[pts.length - 1].value : '-')}</td></tr>`;
      });
      h += '</tbody></table></div>';
    }
  }
  return { html: h, post: () => histories.forEach((hist, i) => { if (hist) multiple('mult-' + i, hist); }) };
}

// multiple draws one small multiple: band as two filled lines, the median,
// and a line per cluster outside the band in the latest scan.
function multiple(id, hist) {
  const pts = hist.points.filter((p) => p.distribution);
  if (!pts.length) return;
  const labels = pts.map((p) => new Date(p.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
  const nonNegative = pts.every((p) => p.distribution.values.every((v) => typeof v.number !== 'number' || v.number >= 0));
  const floor = (n) => (nonNegative ? Math.max(0, n) : n);
  const last = pts[pts.length - 1].distribution;
  const outs = last.values.filter((v) => v.outlier).map((v) => v.cluster).slice(0, 5);
  const valueOf = (p, c) => {
    const v = p.distribution.values.find((x) => x.cluster === c);
    return v && typeof v.number === 'number' ? v.number : null;
  };
  const accent = token('--band-edge');
  const crit = token('--status-crit');
  const datasets = [
    { label: 'band low', data: pts.map((p) => floor(p.distribution.median - p.distribution.band)), borderColor: 'transparent', pointRadius: 0, fill: false },
    { label: 'band', data: pts.map((p) => p.distribution.median + p.distribution.band), borderColor: 'transparent', backgroundColor: token('--band-fill'), pointRadius: 0, fill: '-1' },
    { label: 'median', data: pts.map((p) => p.distribution.median), borderColor: accent, borderWidth: 2, pointRadius: 0, fill: false },
  ].concat(outs.map((c) => ({ label: c, data: pts.map((p) => valueOf(p, c)), borderColor: crit, borderWidth: 1.5, pointRadius: 0, fill: false, spanGaps: true })));
  makeChart(id, {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false, filter: (item) => item.dataset.label !== 'band low' } },
      scales: { x: { ticks: { maxTicksLimit: 4, maxRotation: 0 } }, y: { ...(nonNegative ? { min: 0 } : {}), ticks: { maxTicksLimit: 4 } } },
    },
  });
}
