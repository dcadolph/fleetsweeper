// The incidents page: findings fused by shared root cause.

import { api } from '../api.js';
import { esc, clusterHref, sevTone, emptyState } from '../dom.js';
import { renderBar } from '../shell.js';

// renderIncidents lists the latest scan's incidents.
export async function renderIncidents() {
  renderBar();
  const scans = await api('/scans?limit=1');
  if (!scans || !scans.length) return emptyState('No scans yet, so there are no incidents to correlate.');
  const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
  const incidents = rpt.incidents || [];
  let h = '<h2>Incidents</h2><p class="sub">Correlated findings fused by shared root cause, so you triage one incident instead of a list of symptoms.</p>';
  if (!incidents.length) return h + emptyState('No findings share a root cause in the latest scan, so each one stands alone on the Findings page.');
  incidents.forEach((inc) => {
    const tone = sevTone(inc.severity);
    h += `<div class="fi ${esc(inc.severity)}"><div class="fi-head">` +
      `<span class="tag bg-${tone} c-${tone}">${esc(inc.severity)}</span><span class="tag bg-muted c-t2">${esc(inc.theme)}</span>` +
      (inc.cluster ? `<a class="tag bg-info c-info" href="${esc(clusterHref(inc.cluster))}">${esc(inc.cluster)}</a>` : '') +
      `</div><div class="fi-title">${esc(inc.title)}</div><div class="fi-desc">${esc(inc.summary)}</div>`;
    if (inc.findings && inc.findings.length) {
      h += `<div class="top-rule"><div class="eyebrow mb-4">Fused signals (${inc.findings.length})</div>` +
        inc.findings.map((t) => `<div class="fs-12 c-t2">&bull; ${esc(t)}</div>`).join('') + '</div>';
    }
    h += '</div>';
  });
  return h;
}
