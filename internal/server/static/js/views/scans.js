// Scan history and the report of one stored scan.

import { api, scannerLabel } from '../api.js';
import { esc, scanHref, clusterHref, statusTone, byId, emptyState } from '../dom.js';
import { dateTime } from '../format.js';
import { TIPS, tip } from '../glossary.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { P } from '../router.js';
import { on } from '../actions.js';

let lastScanReport = null;

// renderScans lists the 50 most recent scans.
export async function renderScans() {
  renderBar();
  const scans = await api('/scans?limit=50');
  let h = '<h2>Scan history</h2>';
  if (!scans || !scans.length) return h + emptyState('No scans recorded yet, so the history starts with the first one.');
  scans.forEach((s) => {
    h += `<div class="si"><div><a class="mono" href="${esc(scanHref(s.id))}">${esc(s.id)}</a><br>` +
      `<span class="meta">${esc(dateTime(s.timestamp))} &middot; ${s.clusters ? s.clusters.length : 0} clusters &middot; ${s.scanners ? s.scanners.length : 0} scanners</span></div></div>`;
  });
  return h;
}

// renderScanReport shows the findings and cluster health of the scan in
// P.scanId.
export async function renderScanReport() {
  renderBar();
  let h = '<a class="back" href="#/scans">&larr; Back to scan history</a>';
  let rpt;
  try {
    rpt = await api('/scans/' + encodeURIComponent(P.scanId) + '/report');
  } catch (e) {
    if (e.status !== 404) throw e;
    return h + '<h2>Scan report</h2>' + emptyState('No stored scan has this ID, so it may have aged out of the history.');
  }
  lastScanReport = rpt;
  h += `<h2>Scan report</h2><p class="sub">${esc(rpt.timestamp)} &middot; ${rpt.clusters.length} clusters</p>`;
  if (rpt.brief && rpt.brief.headline) {
    h += '<div class="panel"><div class="eyebrow mb-4">Scan summary</div>' +
      `<div class="fs-14 fw-600 mb-4">${esc(rpt.brief.headline)}</div>` +
      (rpt.brief.lines || []).map((l) => `<div class="fs-12 c-t2">&bull; ${esc(l)}</div>`).join('') + '</div>';
  }
  h += scannerTable(rpt);
  if (rpt.findings && rpt.findings.length) h += `<h3>Findings (${rpt.findings.length})</h3>` + rpt.findings.map(renderFinding).join('');
  if (rpt.cluster_healths && rpt.cluster_healths.length) {
    h += '<h3>Cluster health</h3><div class="g g3">';
    rpt.cluster_healths.forEach((ch) => {
      h += `<a class="cd cc" href="${esc(clusterHref(ch.name))}"><div aria-hidden="true" class="ind fill-${statusTone(ch.status)}"></div>` +
        `<h4>${esc(ch.name)}</h4><div class="row"><span>${esc(ch.kubernetes_version)}</span><span class="val">${ch.healthy_nodes}/${ch.node_count} nodes</span></div></a>`;
    });
    h += '</div>';
  }
  return h;
}

// scannerTable lists every scanner with whether the fleet agreed on it and
// a button for the per-cluster values of each divergent field.
function scannerTable(rpt) {
  const keys = Object.keys(rpt.sections || {}).sort();
  if (!keys.length) return '';
  let h = '<h3>Scanners</h3><div class="tw"><table><thead><tr><th scope="col">Scanner</th><th scope="col">Fleet</th>' +
    '<th scope="col" data-tip="Click a count to see per-cluster values">Divergent fields</th></tr></thead><tbody>';
  keys.forEach((k) => {
    const sec = rpt.sections[k];
    const n = sec.divergences ? sec.divergences.length : 0;
    h += `<tr><td class="fw-500"${tip(k) ? ` data-tip="${esc(tip(k))}"` : ''}>${esc(scannerLabel(k))}</td>` +
      `<td class="${sec.uniform ? 'c-ok' : 'c-crit'}" data-tip="${esc(sec.uniform ? TIPS.uniform : TIPS.divergent)}">${sec.uniform ? 'Uniform' : 'Divergent'}</td>`;
    h += n > 0
      ? `<td class="mono"><button class="btn btn-ac" data-action="scanner-divergences" data-scanner="${esc(k)}">${n} fields</button></td>`
      : '<td class="mono c-t3">0</td>';
    h += '</tr>';
  });
  return h + '</tbody></table></div><div id="scannerDivDetail"></div>';
}

// showScannerDivergences fills the per-field, per-cluster divergence table of
// one scanner.
function showScannerDivergences(key) {
  const rpt = lastScanReport;
  const sec = rpt && rpt.sections && rpt.sections[key];
  const el = byId('scannerDivDetail');
  if (!sec || !sec.divergences || !el) return;
  const clusters = rpt.clusters || [];
  let h = '<div class="panel inset mt-12"><div class="flex between items-center mb-8">' +
    `<h4>${esc(scannerLabel(key))} divergences</h4><button class="btn btn-sm" data-action="clear" data-target="scannerDivDetail">Close</button></div>`;
  h += '<div class="tw"><table><thead><tr><th scope="col">Field</th>' +
    clusters.map((c) => `<th scope="col"><a href="${esc(clusterHref(c))}">${esc(c)}</a></th>`).join('') + '</tr></thead><tbody>';
  sec.divergences.forEach((d) => {
    const first = d.values && d.values[clusters[0]] ? d.values[clusters[0]] : '';
    h += `<tr><td class="fw-500"${tip(d.field) ? ` data-tip="${esc(tip(d.field))}"` : ''}>${esc(d.field)}</td>`;
    clusters.forEach((c) => {
      const val = d.values && d.values[c] ? d.values[c] : '-';
      const diff = val !== first && val !== '-';
      h += `<td class="mono${diff ? ' c-crit fw-600' : ''}">${esc(val)}</td>`;
    });
    h += '</tr>';
  });
  el.innerHTML = h + '</tbody></table></div></div>';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

on('scanner-divergences', (el) => showScannerDivergences(el.dataset.scanner));
