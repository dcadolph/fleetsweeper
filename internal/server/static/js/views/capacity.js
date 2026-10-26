// The capacity page: correlated capacity status per cluster, then the cost
// of drift when a billing CSV is loaded.

import { api } from '../api.js';
import { esc, pct, fmtUSD, clusterHref, statusTone, threshTone, byId } from '../dom.js';
import { TIPS } from '../glossary.js';
import { renderBar } from '../shell.js';

// renderCapacity shows one card per cluster with its correlated signals and
// the cost panel below them.
export async function renderCapacity() {
  renderBar();
  const data = await api('/capacity');
  let h = '<h2>Capacity and cost</h2><p class="sub">Signal-correlated assessment: utilization, pressure, events, and headroom combined</p>';
  h += capacityCards(data.capacity);
  return { html: h + '<div id="costPanel"></div>', post: loadCostPanel };
}

// capacityCards renders one card per cluster.
function capacityCards(capacity) {
  if (!capacity || !capacity.length) return '<div class="empty">No capacity data available.</div>';
  let h = '<div class="g g3">';
  capacity.forEach((ca) => {
    const tone = statusTone(ca.status);
    const signals = [];
    if (ca.has_memory_pressure) signals.push('<span class="c-crit">MemPressure</span>');
    if (ca.has_oom_events) signals.push('<span class="c-crit">OOMKill</span>');
    if (ca.has_scheduling_failures) signals.push('<span class="c-warn">SchedFail</span>');
    if (ca.has_disk_pressure) signals.push('<span class="c-warn">DiskPressure</span>');
    if (!signals.length) signals.push('<span class="c-ok">None</span>');
    h += `<div class="cd cc" data-href="${esc(clusterHref(ca.cluster))}" role="link" tabindex="0"><div class="ind fill-${tone}"></div>` +
      `<h4>${esc(ca.cluster)}</h4><span class="badge bg-${tone} c-${tone}" data-tip="Status based on correlated signals, not just utilization">${esc(ca.status)}</span>` +
      `<div class="row"><span data-tip="${esc(TIPS.avg_cpu_percent)}">CPU</span><span class="val c-${threshTone(ca.cpu_utilization)}">${pct(ca.cpu_utilization)}</span></div>` +
      `<div class="row"><span data-tip="${esc(TIPS.avg_memory_percent)}">Memory</span><span class="val c-${threshTone(ca.memory_utilization)}">${pct(ca.memory_utilization)}</span></div>` +
      `<div class="row"><span data-tip="Percentage of total capacity still unused">Headroom (mem)</span><span class="val">${pct(ca.headroom_memory)}</span></div>` +
      `<div class="row"><span>Nodes</span><span class="val">${ca.healthy_nodes}/${ca.node_count}</span></div>` +
      `<div class="row"><span data-tip="Active pressure conditions and failure events">Signals</span><span class="val">${signals.join(' ')}</span></div>`;
    if (ca.nodes_needed_for_target > 0) {
      h += `<div class="row"><span data-tip="Additional nodes needed to bring memory below 70%">Scale recommendation</span><span class="val c-ac">+${ca.nodes_needed_for_target} node(s)</span></div>`;
    }
    h += `<div class="rec">${esc(ca.recommendation)}</div>`;
    if (ca.group_deviation) h += `<div class="rec italic">${esc(ca.group_deviation)}</div>`;
    h += '</div>';
  });
  return h + '</div>';
}

// costStat renders one labeled figure in the cost summary.
function costStat(label, val, tone, size) {
  return `<div><div class="eyebrow">${esc(label)}</div><div class="${size} fw-700 c-${tone}">${val}</div></div>`;
}

// loadCostPanel fills the cost-correlation panel when a cost CSV is loaded.
function loadCostPanel() {
  const el = byId('costPanel');
  if (!el) return;
  api('/cost').then((d) => {
    if (!d || d.total_fleet_usd <= 0) return;
    const share = Math.round(100 * d.total_drift_usd / d.total_fleet_usd);
    const tone = share >= 15 ? 'crit' : share >= 5 ? 'warn' : 'ok';
    const priced = d.by_cluster ? d.by_cluster.length : 0;
    const missing = d.missing_cost ? d.missing_cost.length : 0;
    let h = `<h3>Cost correlation <span class="fs-12 fw-500 c-t3">(billing period ${esc(d.period || 'n/a')})</span></h3>`;
    h += '<p class="fs-12 c-t2 mb-12">Drift cost estimates the monthly spend attributable to divergence. Per cluster it is ' +
      '<span class="mono c-t1">cost &times; (100 &minus; health score) / 100</span>. A cluster at score 100 attributes nothing; one at score 60 attributes 40% of its bill. The fleet figure sums every priced cluster.</p>';
    h += '<div class="cd mb-12"><div class="cost-stats">' +
      costStat('Drift cost / mo', '$' + fmtUSD(d.total_drift_usd), tone, 'fs-28') +
      costStat('Fleet spend / mo', '$' + fmtUSD(d.total_fleet_usd), 't1', 'fs-18') +
      costStat('Share drifting', share + '%', tone, 'fs-18') +
      costStat('Clusters priced', priced + (missing ? ' of ' + (priced + missing) : ''), 't2', 'fs-18') +
      '</div>' +
      `<div class="share-bar" data-tip="Drift is ${share}% of fleet spend"><div class="fill-${tone}" style="width:${share}%"></div></div>` +
      `<div class="flex between fs-12 c-t3 mt-4"><span>drift $${fmtUSD(d.total_drift_usd)}</span><span>healthy $${fmtUSD(Math.max(0, d.total_fleet_usd - d.total_drift_usd))}</span></div></div>`;
    if (d.by_cluster && d.by_cluster.length) {
      h += '<div class="tw"><table><thead><tr><th>Cluster</th>' +
        '<th data-tip="Monthly cost from the billing CSV">Cost / mo</th>' +
        '<th data-tip="Cluster health score, 0 to 100">Score</th>' +
        '<th data-tip="100 minus the score: the unhealthy fraction of spend">Health gap</th>' +
        '<th data-tip="Cost times health gap: spend attributed to drift">Drift cost</th>' +
        '<th data-tip="This cluster as a share of total drift cost">% of drift</th></tr></thead><tbody>';
      d.by_cluster.slice(0, 12).forEach((c) => {
        const ct = c.score < 60 ? 'crit' : c.score < 80 ? 'warn' : 'ok';
        const of = d.total_drift_usd > 0 ? Math.round(100 * c.drift_usd / d.total_drift_usd) : 0;
        h += `<tr class="click" data-href="${esc(clusterHref(c.cluster))}"><td class="fw-500"><a href="${esc(clusterHref(c.cluster))}">${esc(c.cluster)}</a></td>` +
          `<td class="mono">$${fmtUSD(c.cost_usd)}</td><td class="mono c-${ct}">${c.score}</td><td class="mono c-${ct}">${100 - c.score}%</td>` +
          `<td class="mono ${c.drift_usd > 0 ? 'c-crit' : 'c-t2'}">$${fmtUSD(c.drift_usd)}</td><td class="mono">${of}%</td></tr>`;
      });
      h += '</tbody></table></div>';
      if (d.by_cluster.length > 12) h += `<div class="note mt-4">Showing the top 12 of ${d.by_cluster.length} clusters by drift cost.</div>`;
    }
    if (missing) {
      h += `<div class="note mt-8">No billing row for ${missing} cluster(s): ${d.missing_cost.slice(0, 6).map(esc).join(', ')}${missing > 6 ? ' (+' + (missing - 6) + ' more)' : ''}. They are excluded from the totals.</div>`;
    }
    el.innerHTML = h;
  }).catch(() => {});
}
