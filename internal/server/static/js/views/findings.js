// The findings page: every finding of the latest scan grouped by cluster,
// filterable by text, severity, cluster, and scanner, with CSV and Markdown
// export. The filters live in the URL, as in #/findings?cluster=a&sev=critical,
// so links from other pages land filtered and a reload keeps them.

import { api, scannerLabel } from '../api.js';
import { esc, csvExport, download, clusterHref, byId, emptyState } from '../dom.js';
import { isoDay } from '../format.js';
import { renderBar } from '../shell.js';
import { renderFinding, remediationFor } from '../components/finding.js';
import { P, nav, setQuery } from '../router.js';
import { on, onChange } from '../actions.js';

let findings = [];

// findingsHref returns the link to the findings page with filters, each of
// q, sev, cluster, and scanner optional.
export function findingsHref(filters) {
  const f = filters || {};
  const q = new URLSearchParams();
  ['cluster', 'q', 'scanner', 'sev'].forEach((k) => { if (f[k]) q.set(k, f[k]); });
  const s = q.toString();
  return '#/findings' + (s ? '?' + s : '');
}

// openFindingsFiltered moves to the findings page with the search box set to
// q and, when given, the severity filter set to sev.
export function openFindingsFiltered(q, sev) {
  nav('findings', { query: { q, sev } });
}

// renderFindings builds the findings page for the latest scan.
export async function renderFindings() {
  renderBar('<button class="btn btn-ac" data-action="export-findings">Export CSV</button>' +
    '<button class="btn btn-ac" data-action="export-criticals">Export critical findings (Markdown)</button>');
  const scans = await api('/scans?limit=1');
  if (!scans || !scans.length) return emptyState('No scans yet, so there are no findings to list.');
  const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
  findings = rpt.findings || [];
  const persistence = await persistenceMap();
  const count = (sev) => findings.filter((f) => f.severity === sev).length;
  let h = '<h2>Findings</h2>';
  h += `<p class="sub">${findings.length} findings: <span class="c-crit fw-600">${count('critical')} critical</span>, ` +
    `<span class="c-warn fw-600">${count('warning')} warning</span>, <span class="c-info">${count('info')} info</span></p>`;
  const q = P.query || {};
  const clusters = [...new Set(findings.map((f) => f.cluster))].sort();
  const scanners = [...new Set(findings.map((f) => f.scanner))].sort();
  const options = (list, current) => list.map(([v, l]) => `<option value="${esc(v)}"${v && v === current ? ' selected' : ''}>${esc(l)}</option>`).join('');
  h += '<div class="controls">' +
    `<input type="search" id="fSearch" class="input-w" placeholder="Filter findings..." data-change="filter-findings" aria-label="Filter findings" value="${esc(q.q || '')}">` +
    '<select id="fSev" data-change="filter-findings" aria-label="Severity">' +
    options([['', 'All severities'], ['critical', 'Critical'], ['warning', 'Warning'], ['info', 'Info']], q.sev) + '</select>' +
    '<select id="fCluster" data-change="filter-findings" aria-label="Cluster">' +
    options([['', 'All clusters']].concat(clusters.map((c) => [c, c])), q.cluster) + '</select>' +
    '<select id="fScanner" data-change="filter-findings" aria-label="Scanner">' +
    options([['', 'All scanners']].concat(scanners.map((c) => [c, scannerLabel(c)])), q.scanner) + '</select></div>';
  if (!findings.length) return h + emptyState('The latest scan raised no findings, so the fleet matches its norm.');

  const groups = {};
  findings.forEach((f) => { (groups[f.cluster || 'fleet'] = groups[f.cluster || 'fleet'] || []).push(f); });
  const crits = (k) => groups[k].filter((f) => f.severity === 'critical').length;
  const keys = Object.keys(groups).sort((a, b) => (a === 'fleet' ? -1 : b === 'fleet' ? 1 : crits(b) - crits(a)));
  keys.forEach((cluster) => {
    const list = groups[cluster];
    const gc = crits(cluster);
    const gw = list.filter((f) => f.severity === 'warning').length;
    const tone = gc ? 'crit' : gw ? 'warn' : 'ok';
    h += `<div class="finding-group" data-gcluster="${esc(cluster)}"><div class="group-head"><span aria-hidden="true" class="dot dot-lg fill-${tone}"></span>`;
    h += cluster === 'fleet'
      ? '<span class="fs-14 fw-600">Fleet-wide</span>'
      : `<a class="fs-14 fw-600" href="${esc(clusterHref(cluster))}">${esc(cluster)}</a>`;
    h += `<span class="fs-12 c-t2">${list.length} finding${list.length !== 1 ? 's' : ''}`;
    if (gc) h += ` &middot; <span class="c-crit">${gc} critical</span>`;
    if (gw) h += ` &middot; <span class="c-warn">${gw} warning</span>`;
    h += '</span></div>' + list.map((f) => renderFinding(f, { persistence })).join('') + '</div>';
  });
  return { html: h, post: applyFilters };
}

// persistenceMap maps each finding's fingerprint to its persistence class
// over recent scans, empty when the history is unavailable.
async function persistenceMap() {
  try {
    const resp = await api('/findings/persistence');
    return Object.fromEntries((resp.findings || []).map((p) => [p.fingerprint, p.class]));
  } catch (_) {
    return {};
  }
}

// applyFilters shows the findings matching the search, severity, cluster,
// and scanner controls, hides groups left empty, and writes the filters to
// the URL.
function applyFilters() {
  const raw = (byId('fSearch') || {}).value || '';
  const q = raw.toLowerCase();
  const sev = (byId('fSev') || {}).value || '';
  const cl = (byId('fCluster') || {}).value || '';
  const sc = (byId('fScanner') || {}).value || '';
  document.querySelectorAll('#ct .fi').forEach((el) => {
    const show = (!sev || el.dataset.sev === sev) && (!cl || el.dataset.cluster === cl) && (!sc || el.dataset.scanner === sc) && (!q || el.dataset.text.indexOf(q) >= 0);
    el.classList.toggle('hidden', !show);
  });
  if (P.page === 'findings') setQuery({ q: raw, sev, cluster: cl, scanner: sc });
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
  const date = isoDay(new Date());
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
