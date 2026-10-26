// The clusters page: a health card per known cluster and a sortable,
// filterable, paginated comparison table.

import { api } from '../api.js';
import { esc, pct, csvExport, clusterHref, statusTone, threshTone, byId } from '../dom.js';
import { TIPS } from '../glossary.js';
import { renderBar } from '../shell.js';
import { on, onChange } from '../actions.js';

const CARD_LIMIT = 12;
const STATUS_RANK = { critical: 0, degraded: 1, strained: 1, busy: 2, unknown: 3, healthy: 4 };

let data = null;
let page = 0;
let showAllCards = false;

// renderClusters builds the cluster cards and comparison table.
export async function renderClusters() {
  renderBar('<button class="btn btn-ac" data-action="export-clusters">Export CSV</button>');
  let clusters = await api('/clusters');
  let h = '<h2>Known clusters</h2>';
  if (!clusters || !clusters.length) return h + '<div class="empty">No clusters scanned yet.</div>';
  const scans = await api('/scans?limit=1');
  const healthMap = {};
  let rpt = null;
  if (scans && scans.length) {
    rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
    (rpt.cluster_healths || []).forEach((ch) => { healthMap[ch.name] = ch; });
  }
  clusters = clusters.slice().sort((a, b) => {
    const sa = (healthMap[a.name] || {}).status || 'unknown';
    const sb = (healthMap[b.name] || {}).status || 'unknown';
    return (STATUS_RANK[sa] ?? 3) - (STATUS_RANK[sb] ?? 3);
  });
  data = { clusters, healthMap, rpt };
  page = 0;

  h += `<p class="sub">${clusters.length} clusters tracked across ${rpt ? rpt.clusters.length : 0} in latest scan</p><div class="g g3">`;
  clusters.forEach((c) => {
    const ch = healthMap[c.name];
    const status = ch ? ch.status : 'unknown';
    const tone = statusTone(status);
    h += `<div class="cd cc" data-cname="${esc((c.name || '').toLowerCase())}" data-href="${esc(clusterHref(c.name))}" role="link" tabindex="0" data-tip="Click for full cluster detail">` +
      `<div class="ind fill-${tone}"></div><h4>${esc(c.name)}</h4><span class="badge bg-${tone} c-${tone === 'muted' ? 't3' : tone}">${esc(status)}</span>`;
    if (ch) {
      const fc = ch.finding_counts || {};
      h += `<div class="row"><span data-tip="${esc(TIPS.git_version)}">Version</span><span class="val">${esc(ch.kubernetes_version || 'N/A')}</span></div>` +
        `<div class="row"><span data-tip="${esc(TIPS.healthy_nodes)}">Nodes</span><span class="val">${ch.healthy_nodes} / ${ch.node_count} healthy</span></div>` +
        `<div class="row"><span data-tip="${esc(TIPS.avg_cpu_percent)}">CPU</span><span class="val c-${threshTone(ch.avg_cpu)}">${pct(ch.avg_cpu)}</span></div>` +
        `<div class="row"><span data-tip="${esc(TIPS.avg_memory_percent)}">Memory</span><span class="val c-${threshTone(ch.avg_memory)}">${pct(ch.avg_memory)}</span></div>` +
        `<div class="row"><span data-tip="${esc(TIPS.warning_events)}">Warning events</span><span class="val${ch.warning_events > 50 ? ' c-warn' : ''}">${ch.warning_events}</span></div>` +
        `<div class="row"><span>Findings</span><span class="val">${fc.critical || 0} critical, ${fc.warning || 0} warn</span></div>`;
    }
    h += `<div class="row"><span>Groups</span><span class="val">${esc(c.groups && c.groups.length ? c.groups.join(', ') : 'none')}</span></div>`;
    const tagKeys = c.tags ? Object.keys(c.tags).sort() : [];
    if (tagKeys.length) {
      h += '<div class="row"><span>Tags</span><span class="val tag-chips">' + tagKeys.map((k) => `<span class="tag-chip">${esc(k)}=${esc(c.tags[k])}</span>`).join('') + '</span></div>';
    }
    h += `<div class="row"><span>First seen</span><span class="val">${esc(new Date(c.first_seen).toLocaleDateString())}</span></div>` +
      `<div class="row"><span>Last seen</span><span class="val">${esc(new Date(c.last_seen).toLocaleDateString())}</span></div></div>`;
  });
  h += '</div><div class="my-8"><button class="btn hidden" id="cardsToggle" data-action="toggle-cards">Show all</button></div>';

  if (rpt && rpt.cluster_healths && rpt.cluster_healths.length > 1) {
    h += '<h3 id="cluster-cmp">Cluster comparison</h3><div class="controls">' +
      '<input id="cSearch" type="search" class="grow" placeholder="Filter clusters..." data-change="cluster-table" aria-label="Filter clusters">' +
      '<select id="cSort" data-change="cluster-table" aria-label="Sort"><option value="status">Sort: Status</option><option value="name">Sort: Name</option><option value="cpu">Sort: CPU</option><option value="mem">Sort: Memory</option><option value="headroom">Sort: Headroom</option><option value="findings">Sort: Findings</option></select>' +
      '<select id="cSize" data-change="cluster-page-size" aria-label="Page size"><option value="25">25 / page</option><option value="50">50 / page</option><option value="100">100 / page</option><option value="all">All</option></select></div>';
    h += '<div class="tw"><table><thead><tr><th>Cluster</th>' +
      '<th data-tip="Correlated status: healthy, busy, degraded, or critical. Based on utilization + pressure + events, not just percentages.">Status</th>' +
      `<th data-tip="${esc(TIPS.git_version)}">Version</th>` +
      '<th data-tip="Total node count. Different clusters may intentionally have different node counts.">Nodes</th>' +
      `<th data-tip="${esc(TIPS.avg_cpu_percent)}">CPU</th><th data-tip="${esc(TIPS.avg_memory_percent)}">Memory</th>` +
      '<th data-tip="Percentage of memory capacity still unused. Lower headroom means less ability to absorb traffic spikes.">Headroom</th>' +
      '<th data-tip="Active pressure conditions or failure events detected on this cluster">Signals</th>' +
      '<th data-tip="Namespaces missing PSS enforce labels. A security gap, not expected to vary.">PSS gaps</th>' +
      '<th data-tip="Namespaces with no NetworkPolicy. A security gap, not expected to vary.">NetPol gaps</th>' +
      '<th data-tip="Number of critical and warning findings for this cluster">Findings</th></tr></thead><tbody id="clusterCmpBody"></tbody></table></div>' +
      '<div id="clusterPager" class="pager"></div>';
  }
  return { html: h, post: renderTable };
}

// tableRows derives one comparison record per cluster in the latest report.
function tableRows() {
  const rpt = data.rpt;
  const capMap = {};
  (rpt.capacity || []).forEach((ca) => { capMap[ca.cluster] = ca; });
  const perCluster = (scanner) => (rpt.sections && rpt.sections[scanner] && rpt.sections[scanner].per_cluster) || {};
  const secU = perCluster('security');
  const secN = perCluster('network-policies');
  return rpt.cluster_healths.map((ch) => {
    const ca = capMap[ch.name] || {};
    const status = ca.status || ch.status;
    const signals = [];
    if (ca.has_memory_pressure) signals.push('MemPressure');
    if (ca.has_oom_events) signals.push('OOMKill');
    if (ca.has_scheduling_failures) signals.push('SchedFail');
    if (ca.has_disk_pressure) signals.push('DiskPressure');
    const fc = ch.finding_counts || {};
    return {
      name: ch.name, status, ver: ch.kubernetes_version || 'N/A', nodes: ch.node_count, cpu: ch.avg_cpu, mem: ch.avg_memory,
      headroom: ca.headroom_memory, rec: ca.recommendation || '', signals,
      unenforced: (secU[ch.name] || {}).unenforced_count || 0, npGaps: (secN[ch.name] || {}).namespaces_without_policies || 0,
      crit: fc.critical || 0, warn: fc.warning || 0, rank: STATUS_RANK[status] ?? 3,
    };
  });
}

// renderTable filters, sorts, and paginates the comparison table, then
// filters the cards to match.
function renderTable() {
  const q = ((byId('cSearch') || {}).value || '').toLowerCase();
  filterCards(q);
  const tb = byId('clusterCmpBody');
  if (!data || !data.rpt || !data.rpt.cluster_healths || !tb) return;
  let rows = tableRows();
  if (q) rows = rows.filter((r) => r.name.toLowerCase().includes(q) || (r.status || '').toLowerCase().includes(q));
  const weight = (r) => r.crit * 10 + r.warn;
  const sorts = {
    name: (a, b) => a.name.localeCompare(b.name),
    cpu: (a, b) => b.cpu - a.cpu,
    mem: (a, b) => b.mem - a.mem,
    headroom: (a, b) => (a.headroom ?? 999) - (b.headroom ?? 999),
    findings: (a, b) => weight(b) - weight(a),
    status: (a, b) => (a.rank - b.rank) || (weight(b) - weight(a)),
  };
  rows.sort(sorts[(byId('cSort') || {}).value] || sorts.status);
  const size = (byId('cSize') || {}).value || '25';
  const per = size === 'all' ? Math.max(rows.length, 1) : parseInt(size, 10);
  const pages = Math.max(1, Math.ceil(rows.length / per));
  page = Math.min(Math.max(page, 0), pages - 1);
  const pageRows = rows.slice(page * per, page * per + per);
  tb.innerHTML = pageRows.length ? pageRows.map(rowHTML).join('') : '<tr><td colspan="11" class="empty">No clusters match the filter.</td></tr>';
  const pager = byId('clusterPager');
  if (pager) {
    pager.innerHTML = `<span>${rows.length} clusters</span>` + (pages > 1
      ? `<button class="btn" data-action="cluster-page" data-delta="-1"${page <= 0 ? ' disabled' : ''}>Prev</button><span>Page ${page + 1} / ${pages}</span>` +
        `<button class="btn" data-action="cluster-page" data-delta="1"${page >= pages - 1 ? ' disabled' : ''}>Next</button>`
      : '');
  }
}

// rowHTML renders one comparison row.
function rowHTML(r) {
  const hrTone = r.headroom < 15 ? 'crit' : r.headroom < 30 ? 'warn' : 'ok';
  return `<tr><td class="fw-500"><a href="${esc(clusterHref(r.name))}">${esc(r.name)}</a></td>` +
    `<td class="c-${statusTone(r.status) === 'muted' ? 't3' : statusTone(r.status)} fw-600" data-tip="${esc(r.rec)}">${esc(r.status)}</td>` +
    `<td class="mono">${esc(r.ver)}</td><td class="mono">${r.nodes}</td>` +
    `<td class="mono c-${threshTone(r.cpu)}">${pct(r.cpu)}</td><td class="mono c-${threshTone(r.mem)}">${pct(r.mem)}</td>` +
    `<td class="mono c-${hrTone}">${r.headroom != null ? pct(r.headroom) : 'N/A'}</td>` +
    `<td class="fs-12">${r.signals.length ? `<span class="c-crit">${esc(r.signals.join(', '))}</span>` : '<span class="c-ok">clean</span>'}</td>` +
    `<td class="mono${r.unenforced > 0 ? ' c-warn' : ''}">${r.unenforced}</td><td class="mono${r.npGaps > 0 ? ' c-warn' : ''}">${r.npGaps}</td>` +
    `<td class="mono">${r.crit ? `<span class="c-crit">${r.crit}c</span>` : '0c'} / ${r.warn ? `<span class="c-warn">${r.warn}w</span>` : '0w'}</td></tr>`;
}

// filterCards hides cards that do not match q and caps how many show until
// the toggle or a search reveals the rest.
function filterCards(q) {
  const cards = document.querySelectorAll('.cd.cc[data-cname]');
  let shown = 0;
  cards.forEach((card) => {
    const match = !q || card.dataset.cname.includes(q);
    const visible = match && (showAllCards || !!q || shown < CARD_LIMIT);
    card.classList.toggle('hidden', !visible);
    if (visible) shown++;
  });
  const btn = byId('cardsToggle');
  if (btn) {
    btn.classList.toggle('hidden', !!q || cards.length <= CARD_LIMIT);
    btn.textContent = showAllCards ? 'Show fewer' : 'Show all ' + cards.length;
  }
}

onChange('cluster-table', renderTable);
onChange('cluster-page-size', () => {
  page = 0;
  renderTable();
});
on('cluster-page', (btn) => {
  page += Number(btn.dataset.delta);
  renderTable();
});
on('toggle-cards', () => {
  showAllCards = !showAllCards;
  filterCards(((byId('cSearch') || {}).value || '').toLowerCase());
});
on('export-clusters', () => {
  if (!data) return;
  csvExport('fleetsweeper-clusters.csv',
    ['Cluster', 'Status', 'Version', 'Nodes', 'Healthy', 'CPU%', 'Mem%', 'Warnings', 'Critical', 'Warnings', 'Groups', 'First Seen', 'Last Seen'],
    data.clusters.map((c) => {
      const ch = data.healthMap[c.name] || {};
      const fc = ch.finding_counts || {};
      return [c.name, ch.status || 'unknown', ch.kubernetes_version || '', ch.node_count || 0, ch.healthy_nodes || 0,
        ch.avg_cpu ? Math.round(ch.avg_cpu) : '', ch.avg_memory ? Math.round(ch.avg_memory) : '', ch.warning_events || 0,
        fc.critical || 0, fc.warning || 0, (c.groups || []).join(';'), c.first_seen, c.last_seen];
    }));
});
