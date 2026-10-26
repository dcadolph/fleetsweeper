// Scan history and the report of one stored scan.

import { api } from '../api.js';
import { esc, scanHref, clusterHref, statusTone } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { P } from '../router.js';

// renderScans lists the 50 most recent scans.
export async function renderScans() {
  renderBar();
  const scans = await api('/scans?limit=50');
  let h = '<h2>Scan history</h2>';
  if (!scans || !scans.length) return h + '<div class="empty">No scans recorded.</div>';
  scans.forEach((s) => {
    h += `<div class="si"><div><a class="mono" href="${esc(scanHref(s.id))}">${esc(s.id)}</a><br>` +
      `<span class="meta">${esc(new Date(s.timestamp).toLocaleString())} &middot; ${s.clusters ? s.clusters.length : 0} clusters &middot; ${s.scanners ? s.scanners.length : 0} scanners</span></div></div>`;
  });
  return h;
}

// renderScanReport shows the findings and cluster health of the scan in
// P.scanId.
export async function renderScanReport() {
  renderBar();
  const rpt = await api('/scans/' + encodeURIComponent(P.scanId) + '/report');
  let h = '<a class="back" href="#/scans">&larr; Back to scan history</a>';
  h += `<h2>Scan report</h2><p class="sub">${esc(rpt.timestamp)} &middot; ${rpt.clusters.length} clusters</p>`;
  if (rpt.findings && rpt.findings.length) h += `<h3>Findings (${rpt.findings.length})</h3>` + rpt.findings.map(renderFinding).join('');
  if (rpt.cluster_healths && rpt.cluster_healths.length) {
    h += '<h3>Cluster health</h3><div class="g g3">';
    rpt.cluster_healths.forEach((ch) => {
      h += `<div class="cd cc" data-href="${esc(clusterHref(ch.name))}" role="link" tabindex="0"><div class="ind fill-${statusTone(ch.status)}"></div>` +
        `<h4>${esc(ch.name)}</h4><div class="row"><span>${esc(ch.kubernetes_version)}</span><span class="val">${ch.healthy_nodes}/${ch.node_count} nodes</span></div></div>`;
    });
    h += '</div>';
  }
  return h;
}
