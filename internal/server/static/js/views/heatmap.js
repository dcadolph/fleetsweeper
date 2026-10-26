// The fleet heatmap: clusters by scanners, colored by the worst finding in
// each cell.

import { api, scannerLabel } from '../api.js';
import { esc } from '../dom.js';
import { renderBar } from '../shell.js';
import { on } from '../actions.js';
import { openFindingsFiltered } from './findings.js';

const RANK = { critical: 3, warning: 2, info: 1 };
const CELL = { critical: 'cell-crit', warning: 'cell-warn', info: 'cell-info' };

// renderHeatmap draws the matrix for the latest scan.
export async function renderHeatmap() {
  renderBar('');
  const scans = await api('/scans?limit=1');
  if (!scans || !scans.length) return '<div class="empty">No scans yet. Trigger a scan from the Dashboard.</div>';
  const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
  const worst = {};
  const count = {};
  const scannerSet = new Set();
  (rpt.findings || []).forEach((f) => {
    if (!f.scanner || f.cluster === 'fleet') return;
    scannerSet.add(f.scanner);
    const key = f.cluster + '\u0000' + f.scanner;
    if ((RANK[f.severity] || 0) > (RANK[worst[key]] || 0)) worst[key] = f.severity;
    count[key] = (count[key] || 0) + 1;
  });
  const scanners = [...scannerSet].sort();
  if (!scanners.length) return '<div class="empty">No findings to plot.</div>';
  let h = '<h2>Fleet heatmap</h2><p class="sub">Clusters × scanners, colored by worst-severity finding for the cell. Click a cell to open the Findings page filtered to that cluster.</p>';
  h += '<div class="legend mb-8">Legend: <span><span class="swatch bg-ok"></span> ok</span>' +
    '<span><span class="swatch fill-info"></span> info</span><span><span class="swatch fill-warn"></span> warning</span><span><span class="swatch fill-crit"></span> critical</span></div>';
  h += '<div class="tw"><table class="heat"><thead><tr><th></th>' +
    scanners.map((s) => `<th class="vertical-th">${esc(scannerLabel(s))}</th>`).join('') + '</tr></thead><tbody>';
  (rpt.clusters || []).forEach((c) => {
    h += `<tr><td class="fw-500 fs-12 nowrap">${esc(c)}</td>`;
    scanners.forEach((s) => {
      const key = c + '\u0000' + s;
      const n = count[key] || 0;
      const tipText = n ? n + ' ' + (worst[key] || '') + ' finding(s)' : 'no findings';
      h += `<td class="cell ${CELL[worst[key]] || 'cell-ok'}" data-action="heat-cell" data-cluster="${esc(c)}" data-tip="${esc(tipText)}" tabindex="0" role="button">${n || ''}</td>`;
    });
    h += '</tr>';
  });
  return h + '</tbody></table></div>';
}

on('heat-cell', (cell) => openFindingsFiltered(cell.dataset.cluster));
