// The capacity page: correlated capacity status per cluster.

import { api } from '../api.js';
import { esc, pct, clusterHref, statusTone, threshTone } from '../dom.js';
import { TIPS } from '../glossary.js';
import { renderBar } from '../shell.js';

// renderCapacity shows one card per cluster with its correlated signals.
export async function renderCapacity() {
  renderBar();
  const data = await api('/capacity');
  let h = '<h2>Capacity analysis</h2><p class="sub">Signal-correlated assessment: utilization, pressure, events, and headroom combined</p>';
  if (!data.capacity || !data.capacity.length) return h + '<div class="empty">No capacity data available.</div>';
  h += '<div class="g g3">';
  data.capacity.forEach((ca) => {
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
