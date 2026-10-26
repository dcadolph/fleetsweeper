// The findings page: every finding of the latest scan grouped by cluster,
// filterable by text, severity, and cluster, with CSV and Markdown export.

import { api } from '../api.js';
import { esc, csvExport, download, clusterHref, byId } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderFinding, remediationFor } from '../components/finding.js';
import { P } from '../router.js';
import { on, onChange } from '../actions.js';

let findings = [];

// openFindingsFiltered moves to the findings page with the search box set to
// q.
export function openFindingsFiltered(q) {
  P.findingsQuery = q;
  if (location.hash === '#/findings') {
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  } else {
    location.hash = '#/findings';
  }
}

// renderFindings builds the findings page for the latest scan.
export async function renderFindings() {
  renderBar('<button class="btn btn-ac" data-action="export-findings">Export CSV</button>' +
    '<button class="btn btn-ac" data-action="export-criticals">Export critical findings (Markdown)</button>');
  const scans = await api('/scans?limit=1');
  if (!scans || !scans.length) return '<div class="empty">No scans.</div>';
  const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
  findings = rpt.findings || [];
  const count = (sev) => findings.filter((f) => f.severity === sev).length;
  let h = '<h2>Findings</h2>';
  h += `<p class="sub">${findings.length} findings: <span class="c-crit fw-600">${count('critical')} critical</span>, ` +
    `<span class="c-warn fw-600">${count('warning')} warning</span>, <span class="c-info">${count('info')} info</span></p>`;
  const clusters = [...new Set(findings.map((f) => f.cluster))].sort();
  h += '<div class="controls">' +
    `<input type="search" id="fSearch" class="input-w" placeholder="Filter findings..." data-change="filter-findings" aria-label="Filter findings" value="${esc(P.findingsQuery || '')}">` +
    '<select id="fSev" data-change="filter-findings" aria-label="Severity"><option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>' +
    '<select id="fCluster" data-change="filter-findings" aria-label="Cluster"><option value="">All clusters</option>' +
    clusters.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join('') + '</select></div>';
  P.findingsQuery = '';
  if (!findings.length) return h + '<div class="empty">No findings. Fleet is healthy.</div>';

  const groups = {};
  findings.forEach((f) => { (groups[f.cluster || 'fleet'] = groups[f.cluster || 'fleet'] || []).push(f); });
  const crits = (k) => groups[k].filter((f) => f.severity === 'critical').length;
  const keys = Object.keys(groups).sort((a, b) => (a === 'fleet' ? -1 : b === 'fleet' ? 1 : crits(b) - crits(a)));
  keys.forEach((cluster) => {
    const list = groups[cluster];
    const gc = crits(cluster);
    const gw = list.filter((f) => f.severity === 'warning').length;
    const tone = gc ? 'crit' : gw ? 'warn' : 'ok';
    h += `<div class="finding-group" data-gcluster="${esc(cluster)}"><div class="group-head"><span class="dot dot-lg fill-${tone}"></span>`;
    h += cluster === 'fleet'
      ? '<span class="fs-14 fw-600">Fleet-wide</span>'
      : `<a class="fs-14 fw-600" href="${esc(clusterHref(cluster))}">${esc(cluster)}</a>`;
    h += `<span class="fs-12 c-t2">${list.length} finding${list.length !== 1 ? 's' : ''}`;
    if (gc) h += ` &middot; <span class="c-crit">${gc} critical</span>`;
    if (gw) h += ` &middot; <span class="c-warn">${gw} warning</span>`;
    h += '</span></div>' + list.map(renderFinding).join('') + '</div>';
  });
  return { html: h, post: applyFilters };
}

// applyFilters shows the findings matching the search, severity, and cluster
// controls, and hides groups left empty.
function applyFilters() {
  const q = ((byId('fSearch') || {}).value || '').toLowerCase();
  const sev = (byId('fSev') || {}).value || '';
  const cl = (byId('fCluster') || {}).value || '';
  document.querySelectorAll('.fi').forEach((el) => {
    const show = (!sev || el.dataset.sev === sev) && (!cl || el.dataset.cluster === cl) && (!q || el.dataset.text.indexOf(q) >= 0);
    el.classList.toggle('hidden', !show);
  });
  document.querySelectorAll('.finding-group').forEach((g) => {
    g.classList.toggle('hidden', !g.querySelector('.fi:not(.hidden)'));
  });
}

onChange('filter-findings', applyFilters);

on('export-findings', () => {
  csvExport('fleetsweeper-findings.csv', ['Severity', 'Cluster', 'Scanner', 'Title', 'Description'],
    findings.map((f) => [f.severity, f.cluster, f.scanner, f.title, f.description]));
});

on('export-criticals', () => {
  const date = new Date().toISOString().slice(0, 10);
  const lines = ['## Critical findings: ' + date, ''];
  const crit = findings.filter((f) => f.severity === 'critical');
  if (!crit.length) lines.push('_No critical findings._');
  crit.forEach((f) => {
    lines.push('- **' + (f.cluster || 'fleet') + '**: ' + f.title);
    const rem = remediationFor(f);
    if (rem && rem.length) {
      lines.push('  ```');
      rem.join('\n').split('\n').forEach((l) => lines.push('  ' + l));
      lines.push('  ```');
    }
  });
  download('fleetsweeper-criticals-' + date + '.md', lines.join('\n') + '\n', 'text/markdown');
});
