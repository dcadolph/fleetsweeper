// The trends page: trend findings and the direction of each tracked field.

import { api } from '../api.js';
import { esc } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';

// renderTrends shows fleet trends over the last 20 scans.
export async function renderTrends() {
  renderBar();
  const data = await api('/trends?scans=20');
  let h = '<h2>Fleet trends</h2>';
  if (data.message) return h + '<div class="empty">' + esc(data.message) + '</div>';
  if (data.findings && data.findings.length) h += '<h3>Trend findings</h3>' + data.findings.map(renderFinding).join('');
  if (data.fleet_trends && data.fleet_trends.length) {
    h += '<h3>Fleet drift over time</h3><div class="tw"><table><thead><tr><th>Scanner</th><th>Field</th><th>Direction</th><th>Points</th><th>First value</th><th>Last value</th></tr></thead><tbody>';
    data.fleet_trends.forEach((t) => {
      const tone = t.direction === 'worsening' ? 'crit' : t.direction === 'improving' ? 'ok' : 't2';
      const pts = t.points || [];
      h += `<tr><td>${esc(t.scanner)}</td><td>${esc(t.field)}</td><td class="c-${tone} fw-600">${esc(t.direction)}</td><td>${pts.length}</td>` +
        `<td class="mono">${esc(pts.length ? pts[0].value : '-')}</td><td class="mono">${esc(pts.length ? pts[pts.length - 1].value : '-')}</td></tr>`;
    });
    h += '</tbody></table></div>';
  }
  return h;
}
