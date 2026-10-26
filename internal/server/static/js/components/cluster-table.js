// The worst-clusters table: one row per cluster with its status, the score
// points it costs, its deviation mass, its finding counts, CPU and memory as
// inline bars, and its projected score move. Headers sort; the first rows show
// until the viewer asks for every cluster.

import { esc, clusterHref, statusTone, threshTone, pct, byId } from '../dom.js';
import { fmt } from '../viz.js';
import { on } from '../actions.js';

// SHOWN is how many rows show before the viewer expands the table.
const SHOWN = 10;

// STATUS_RANK orders statuses worst first.
const STATUS_RANK = { critical: 0, degraded: 1, busy: 2, healthy: 3 };

// COLUMNS lists the sortable columns: key, header, tooltip, whether larger
// sorts first, and the numeric value of a row.
const COLUMNS = [
  { key: 'cluster', label: 'Cluster', value: (r) => r.cluster },
  { key: 'status', label: 'Status', tip: 'Correlated status from findings and utilization.', value: (r) => STATUS_RANK[r.status] ?? 4 },
  { key: 'cost', label: 'Score cost', tip: 'Fleet score points this cluster costs.', desc: true, value: (r) => r.cost },
  { key: 'mass', label: 'Deviation', tip: 'Deviation mass: the sum of capped |z| over every field, how far the cluster sits from the norm.', desc: true, value: (r) => r.mass },
  { key: 'critical', label: 'Critical', desc: true, value: (r) => r.critical },
  { key: 'warning', label: 'Warning', desc: true, value: (r) => r.warning },
  { key: 'cpu', label: 'CPU', desc: true, value: (r) => r.cpu },
  { key: 'memory', label: 'Memory', desc: true, value: (r) => r.memory },
  { key: 'projected', label: 'Projected', tip: 'Linear projection of the cluster score at the next scan, against now.', value: (r) => (r.projected == null ? Infinity : r.projected) },
];

const state = { rows: [], sort: null, all: false };

// defaultOrder sorts worst first: status, then score cost, then deviation.
function defaultOrder(a, b) {
  return ((STATUS_RANK[a.status] ?? 4) - (STATUS_RANK[b.status] ?? 4)) || (b.cost - a.cost) || (b.mass - a.mass) || a.cluster.localeCompare(b.cluster);
}

// sortedRows returns the rows in the current order.
export function sortedRows(rows, sort) {
  const out = rows.slice();
  if (!sort) return out.sort(defaultOrder);
  const col = COLUMNS.find((c) => c.key === sort.key);
  if (!col) return out.sort(defaultOrder);
  const dir = sort.desc ? -1 : 1;
  return out.sort((a, b) => {
    const va = col.value(a);
    const vb = col.value(b);
    const cmp = typeof va === 'string' ? va.localeCompare(vb) : va - vb;
    return cmp * dir || defaultOrder(a, b);
  });
}

// bar renders a utilization value as an inline bar and its percentage.
function bar(v) {
  if (typeof v !== 'number') return '<span class="c-t3">n/a</span>';
  const w = Math.max(0, Math.min(100, v));
  return `<span class="ubar-cell"><svg class="ubar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">` +
    `<rect class="ubar-track" width="100" height="6" rx="3"/><rect class="ubar-${threshTone(v)}" width="${w.toFixed(1)}" height="6" rx="3"/></svg>` +
    `<span class="mono">${pct(v)}</span></span>`;
}

// projectedCell renders the projected move, or a dash when there is no fit.
function projectedCell(r) {
  if (r.projected == null) return '<span class="c-t3" data-tip="Not enough scans to project.">&ndash;</span>';
  const tone = r.projected < 0 ? 'crit' : r.projected > 0 ? 'ok' : 't2';
  return `<span class="mono c-${tone}">${r.projected > 0 ? '+' : ''}${r.projected}</span>`;
}

// rowHTML renders one row.
function rowHTML(r) {
  const tone = statusTone(r.status);
  return `<tr class="click" data-href="${esc(clusterHref(r.cluster))}"><td class="fw-500"><a href="${esc(clusterHref(r.cluster))}">${esc(r.cluster)}</a></td>` +
    `<td><span class="pill bg-${tone} c-${tone === 'muted' ? 't2' : tone}">${esc(r.status)}</span></td>` +
    `<td class="mono">${r.cost > 0 ? esc(fmt(Math.round(r.cost * 10) / 10)) : '<span class="c-t3">0</span>'}</td>` +
    `<td class="mono">${esc(fmt(Math.round(r.mass * 10) / 10))}</td>` +
    `<td class="mono${r.critical ? ' c-crit fw-600' : ' c-t3'}">${r.critical}</td>` +
    `<td class="mono${r.warning ? ' c-warn' : ' c-t3'}">${r.warning}</td>` +
    `<td>${bar(r.cpu)}</td><td>${bar(r.memory)}</td><td>${projectedCell(r)}</td></tr>`;
}

// bodyHTML renders the table body and the expand control for the state.
function bodyHTML() {
  const rows = sortedRows(state.rows, state.sort);
  const shown = state.all ? rows : rows.slice(0, SHOWN);
  const head = COLUMNS.map((c) => {
    const on = state.sort && state.sort.key === c.key;
    const aria = on ? (state.sort.desc ? 'descending' : 'ascending') : 'none';
    return `<th aria-sort="${aria}"${c.tip ? ` data-tip="${esc(c.tip)}"` : ''}><button class="th-sort" data-action="ctable-sort" data-key="${c.key}">` +
      `${esc(c.label)}${on ? (state.sort.desc ? ' &#9660;' : ' &#9650;') : ''}</button></th>`;
  }).join('');
  let h = `<div class="tw"><table class="ctable"><thead><tr>${head}</tr></thead><tbody>${shown.map(rowHTML).join('')}</tbody></table></div>`;
  if (rows.length > SHOWN) {
    h += `<button class="btn btn-sm mt-8" data-action="ctable-all">${state.all ? 'Show the worst only' : 'Show every cluster'}</button>`;
  }
  return h;
}

// renderClusterTable returns the table for rows, each {cluster, status, cost,
// mass, critical, warning, cpu, memory, projected}, worst first. The viewer's
// sort and expansion carry over to the next render, so a live refresh keeps
// them.
export function renderClusterTable(rows) {
  state.rows = rows || [];
  if (!state.rows.length) return '<div class="empty">No clusters in the latest scan.</div>';
  return `<div id="clusterTable" data-tour="cluster-table">${bodyHTML()}</div>`;
}

// repaint redraws the table in place.
function repaint() {
  const el = byId('clusterTable');
  if (el) el.innerHTML = bodyHTML();
}

on('ctable-sort', (btn) => {
  const col = COLUMNS.find((c) => c.key === btn.dataset.key);
  if (!col) return;
  state.sort = state.sort && state.sort.key === col.key
    ? { key: col.key, desc: !state.sort.desc }
    : { key: col.key, desc: !!col.desc };
  repaint();
});

on('ctable-all', () => {
  state.all = !state.all;
  repaint();
});
