// The cluster detail page: status line, gauges, findings, and one collapsible
// section per scanner the cluster reported.

import { api } from '../api.js';
import { esc, pct, csvExport, statusTone, threshTone } from '../dom.js';
import { TIPS } from '../glossary.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { percentDoughnut, partDoughnut } from '../charts.js';
import { P } from '../router.js';
import { on, onChange } from '../actions.js';

let lastDetail = null;

// stat renders one labeled value tile.
function stat(value, label, tone, tipText) {
  return `<div class="cd st"${tipText ? ` data-tip="${esc(tipText)}"` : ''}><div class="v${tone ? ' c-' + tone : ''}">${esc(value)}</div><div class="l">${esc(label)}</div></div>`;
}

// flagTone returns crit for a set flag and ok otherwise.
function flagTone(v, bad) {
  return v ? bad || 'crit' : 'ok';
}

// section renders a collapsible scanner section, open when it has a problem.
function section(title, id, content, hasProblem) {
  return `<div class="dsec${hasProblem ? ' open' : ''}" id="dsec-${id}">` +
    `<button class="dsec-h" data-action="toggle-section" aria-expanded="${hasProblem ? 'true' : 'false'}"><h4>${esc(title)}</h4><span class="chev" aria-hidden="true">&#9654;</span></button>` +
    `<div class="dsec-b">${content}</div></div>`;
}

// table renders a table from headers and rows of pre-rendered cells.
function table(headers, rows, id) {
  return `<div class="tw"><table${id ? ` id="${id}"` : ''}><thead><tr>${headers.join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

// th renders a header cell with an optional tooltip.
function th(label, tipText) {
  return `<th${tipText ? ` data-tip="${esc(tipText)}"` : ''}>${esc(label)}</th>`;
}

// renderDetail builds the detail page of the cluster in P.cluster.
export async function renderDetail() {
  renderBar('<button class="btn btn-ac" data-action="export-cluster">Export all data</button> <button class="btn" data-action="export-events">Export events</button>');
  const c = P.cluster;
  const data = await api('/clusters/' + encodeURIComponent(c) + '/detail');
  lastDetail = data;
  const sd = data.scanner_data || {};
  const ch = data.health;
  let h = '<a class="back" href="#/">&larr; Back to dashboard</a>';
  h += `<h2>${esc(c)}</h2>`;
  if (ch) {
    const tone = statusTone(ch.status);
    h += `<p class="sub flex items-center gap-6"><span class="dot dot-lg fill-${tone}"></span><b>${esc(ch.status)}</b> &middot; ${esc(ch.kubernetes_version)} &middot; ${ch.node_count} nodes &middot; CPU ${pct(ch.avg_cpu)} &middot; Mem ${pct(ch.avg_memory)} &middot; ${ch.warning_events} warning events</p>`;
    h += '<div class="g g4">' +
      '<div class="chc"><h4>CPU</h4><canvas id="detCpu" height="120"></canvas></div>' +
      '<div class="chc"><h4>Memory</h4><canvas id="detMem" height="120"></canvas></div>' +
      '<div class="chc"><h4>Nodes</h4><canvas id="detNodes" height="120"></canvas></div>' +
      '<div class="chc"><h4>Security posture</h4><canvas id="detSec" height="120"></canvas></div></div>';
  }
  if (data.findings && data.findings.length) {
    h += `<h3 data-tour="findings-list">Findings (${data.findings.length})</h3>` + data.findings.map(renderFinding).join('');
  }
  h += sections(sd);

  return {
    html: h,
    post() {
      if (!ch) return;
      percentDoughnut('detCpu', ch.avg_cpu, 'CPU');
      percentDoughnut('detMem', ch.avg_memory, 'Memory');
      partDoughnut('detNodes', ['Healthy', 'Unhealthy'], ch.healthy_nodes, ch.node_count - ch.healthy_nodes, 'Nodes', 'crit');
      const enf = sd.security ? sd.security.enforced_count || 0 : 0;
      const unenf = sd.security ? sd.security.unenforced_count || 0 : 0;
      if (enf + unenf > 0) partDoughnut('detSec', ['Enforced', 'Unenforced'], enf, unenf, 'PSS', unenf ? 'warn' : 'ok');
    },
  };
}

// sections renders one section per scanner the cluster reported.
function sections(sd) {
  let h = '';
  if (sd.version) {
    const v = sd.version;
    h += section('Kubernetes Version', 'version', `<div class="g g6">${stat(v.git_version, 'Version', 'ac')}${stat(v.platform, 'Platform')}</div>`);
  }
  if (sd['node-health']) {
    const nh = sd['node-health'];
    let c = '<div class="g g6">' +
      stat(nh.healthy_nodes, 'Healthy', 'ok', TIPS.healthy_nodes) +
      stat(nh.unhealthy_nodes, 'Unhealthy', flagTone(nh.unhealthy_nodes), TIPS.unhealthy_nodes) +
      stat(nh.memory_pressure_nodes, 'Mem pressure', flagTone(nh.memory_pressure_nodes), TIPS.memory_pressure_nodes) +
      stat(nh.disk_pressure_nodes, 'Disk pressure', flagTone(nh.disk_pressure_nodes), TIPS.disk_pressure_nodes) +
      stat(nh.not_ready_nodes, 'Not ready', flagTone(nh.not_ready_nodes), TIPS.not_ready_nodes) +
      stat(nh.unschedulable_nodes, 'Cordoned', flagTone(nh.unschedulable_nodes, 'warn'), TIPS.unschedulable_nodes) + '</div>';
    if (nh.nodes && nh.nodes.length) {
      c += table(['Node', 'Ready', 'Mem pressure', 'Disk pressure', 'PID pressure', 'Net unavailable', 'Cordoned'].map((x) => th(x)),
        nh.nodes.map((n) => `<tr><td class="mono fw-500">${esc(n.name)}</td><td class="c-${n.ready ? 'ok' : 'crit'}">${n.ready}</td>` +
          `<td class="c-${flagTone(n.memory_pressure)}">${n.memory_pressure}</td><td class="c-${flagTone(n.disk_pressure)}">${n.disk_pressure}</td>` +
          `<td class="c-${flagTone(n.pid_pressure)}">${n.pid_pressure}</td><td class="c-${flagTone(n.network_unavailable)}">${n.network_unavailable}</td>` +
          `<td class="c-${flagTone(n.unschedulable, 'warn')}">${n.unschedulable}</td></tr>`));
    }
    h += section(`Node Health (${nh.node_count} nodes)`, 'node-health', c, nh.unhealthy_nodes > 0);
  }
  if (sd.metrics && sd.metrics.available) {
    const m = sd.metrics;
    let c = '<div class="g g6">' +
      stat(Math.round(m.avg_cpu_percent) + '%', 'Avg CPU', threshTone(m.avg_cpu_percent), TIPS.avg_cpu_percent) +
      stat(Math.round(m.max_cpu_percent) + '%', `Peak CPU (${m.max_cpu_node})`, threshTone(m.max_cpu_percent), TIPS.max_cpu_percent) +
      stat(Math.round(m.avg_memory_percent) + '%', 'Avg Mem', threshTone(m.avg_memory_percent), TIPS.avg_memory_percent) +
      stat(Math.round(m.max_memory_percent) + '%', `Peak Mem (${m.max_memory_node})`, threshTone(m.max_memory_percent), TIPS.max_memory_percent) + '</div>';
    if (m.nodes && m.nodes.length) {
      c += table(['Node', 'CPU usage', 'CPU %', 'Memory usage', 'Memory %'].map((x) => th(x)),
        m.nodes.map((n) => `<tr><td class="mono fw-500">${esc(n.name)}</td><td class="mono">${esc(n.cpu_usage)}</td>` +
          `<td class="mono c-${threshTone(n.cpu_percent)}">${n.cpu_percent >= 0 ? Math.round(n.cpu_percent) + '%' : 'N/A'}</td>` +
          `<td class="mono">${esc(n.memory_usage)}</td><td class="mono c-${threshTone(n.memory_percent)}">${n.memory_percent >= 0 ? Math.round(n.memory_percent) + '%' : 'N/A'}</td></tr>`));
    }
    h += section('Resource Utilization', 'metrics', c, m.avg_memory_percent > 70 || m.avg_cpu_percent > 70);
  }
  if (sd.resources) {
    const r = sd.resources;
    let c = `<div class="g g6">${stat(r.node_count, 'Nodes')}${stat(r.ready_nodes, 'Ready')}${stat(r.total_allocatable_cpu, 'Total CPU')}${stat(r.total_allocatable_memory, 'Total memory')}</div>`;
    if (r.nodes && r.nodes.length) {
      c += table(['Node', 'Alloc. CPU', 'Alloc. memory', 'Capacity CPU', 'Capacity memory', 'Cordoned'].map((x) => th(x)),
        r.nodes.map((n) => `<tr><td class="mono fw-500">${esc(n.name)}</td><td class="mono">${esc(n.allocatable_cpu)}</td><td class="mono">${esc(n.allocatable_memory)}</td>` +
          `<td class="mono">${esc(n.capacity_cpu)}</td><td class="mono">${esc(n.capacity_memory)}</td><td class="c-${flagTone(n.unschedulable, 'warn')}">${n.unschedulable}</td></tr>`));
    }
    h += section('Node Resources', 'resources', c);
  }
  if (sd.events) {
    const ev = sd.events;
    let c = `<div class="g g3">${stat(ev.total_events, 'Total events')}${stat(ev.warning_events, 'Warnings', ev.warning_events > 50 ? 'crit' : ev.warning_events > 0 ? 'warn' : 'ok')}${stat(ev.normal_events, 'Normal', 'ok')}</div>`;
    if (ev.top_warning_reasons && ev.top_warning_reasons.length) {
      c += '<h4 class="my-8">Top warning reasons</h4>' + table([th('Reason'), th('Total count', 'Total occurrences across all events with this reason'), th('Distinct events', 'Number of distinct event objects')],
        ev.top_warning_reasons.map((r) => `<tr><td class="fw-500 c-warn">${esc(r.reason)}</td><td class="mono">${r.count}</td><td class="mono">${r.event_count}</td></tr>`));
    }
    if (ev.recent_warnings && ev.recent_warnings.length) {
      c += `<h4 class="my-8">Recent warning events (${ev.recent_warnings.length})</h4>` +
        '<input type="search" class="input-w mb-8" placeholder="Filter events..." data-change="filter-events" aria-label="Filter events">' +
        table(['Namespace', 'Kind', 'Object', 'Reason', 'Message', 'Count', 'Last seen'].map((x) => th(x)),
          ev.recent_warnings.map((e) => {
            const txt = [e.namespace, e.kind, e.involved_object, e.reason, e.message].join(' ').toLowerCase();
            return `<tr data-evtext="${esc(txt)}"><td class="mono">${esc(e.namespace)}</td><td>${esc(e.kind)}</td><td class="mono">${esc(e.involved_object)}</td>` +
              `<td class="fw-500 c-warn">${esc(e.reason)}</td><td class="td-wrap fs-12">${esc(e.message)}</td><td class="mono">${e.count}</td><td class="mono nowrap">${esc(e.last_seen)}</td></tr>`;
          }), 'evTable');
    }
    h += section('Events', 'events', c, ev.warning_events > 20);
  }
  if (sd.security) {
    const s = sd.security;
    let c = `<div class="g g3">${stat(s.enforced_count || 0, 'PSS enforced', 'ok', TIPS.enforced_count)}${stat(s.unenforced_count, 'Unenforced', flagTone(s.unenforced_count, 'warn'), TIPS.unenforced_count)}${stat(s.namespace_count, 'Namespaces')}</div>`;
    if (s.namespaces && s.namespaces.length) {
      c += table([th('Namespace'), th('Enforce', 'Pod Security Standards enforce level'), th('Enforce version'), th('Audit', 'Audit mode level'), th('Warn', 'Warning mode level')],
        s.namespaces.map((ns) => `<tr><td class="mono fw-500">${esc(ns.namespace)}</td><td class="c-${ns.enforce ? 'ok' : 'warn'}">${esc(ns.enforce || 'none')}</td>` +
          `<td class="mono">${esc(ns.enforce_version || '')}</td><td>${esc(ns.audit || '')}</td><td>${esc(ns.warn || '')}</td></tr>`));
    }
    h += section('Pod Security Standards', 'security', c, s.unenforced_count > 0);
  }
  if (sd['network-policies']) {
    const np = sd['network-policies'];
    let c = `<div class="g g3">${stat(np.count, 'Policies')}${stat(np.namespaces_with_policies, 'Covered namespaces', 'ok', TIPS.namespaces_with_policies)}${stat(np.namespaces_without_policies, 'Uncovered namespaces', flagTone(np.namespaces_without_policies, 'warn'), TIPS.namespaces_without_policies)}</div>`;
    if (np.policies && np.policies.length) {
      c += table([th('Namespace'), th('Policy name'), th('Types', 'Ingress, Egress, or both'), th('Ingress rules'), th('Egress rules')],
        np.policies.map((p) => `<tr><td class="mono">${esc(p.namespace)}</td><td class="mono fw-500">${esc(p.name)}</td><td>${esc((p.policy_types || []).join(', '))}</td>` +
          `<td class="mono">${p.ingress_rule_count}</td><td class="mono">${p.egress_rule_count}</td></tr>`));
    }
    h += section('Network Policies', 'network-policies', c, np.namespaces_without_policies > 0);
  }
  if (sd.rbac) {
    const rb = sd.rbac;
    let c = `<div class="g g6">${stat(rb.cluster_role_count, 'ClusterRoles')}${stat(rb.role_count, 'Roles')}${stat(rb.cluster_role_binding_count, 'ClusterRoleBindings')}${stat(rb.role_binding_count, 'RoleBindings')}</div>`;
    if (rb.roles && rb.roles.length) {
      c += `<h4 class="my-8">Roles (${rb.roles.length})</h4>` + table([th('Kind'), th('Namespace'), th('Name'), th('Rules', 'Number of RBAC policy rules')],
        rb.roles.map((r) => `<tr><td>${esc(r.kind)}</td><td class="mono">${esc(r.namespace || 'cluster-wide')}</td><td class="mono fw-500">${esc(r.name)}</td><td class="mono">${r.rule_count}</td></tr>`));
    }
    if (rb.bindings && rb.bindings.length) {
      c += `<h4 class="my-8">Bindings (${rb.bindings.length})</h4>` + table([th('Kind'), th('Namespace'), th('Name'), th('Role ref'), th('Subjects', 'Number of subjects (users, groups, service accounts) bound')],
        rb.bindings.map((b) => `<tr><td>${esc(b.kind)}</td><td class="mono">${esc(b.namespace || 'cluster-wide')}</td><td class="mono fw-500">${esc(b.name)}</td><td class="mono">${esc(b.role_ref)}</td><td class="mono">${b.subject_count}</td></tr>`));
    }
    h += section('RBAC', 'rbac', c);
  }
  if (sd.namespaces) {
    const ns = sd.namespaces;
    let c = `<div class="inline-stat">${stat(ns.count, 'Namespaces')}</div>`;
    if (ns.names && ns.names.length) {
      c += table([th('Namespace'), th('Labels')], ns.names.map((n) => {
        const lbls = ns.labels && ns.labels[n] ? Object.entries(ns.labels[n]).map((e) => e[0] + '=' + e[1]).join(', ') : '';
        return `<tr><td class="mono fw-500">${esc(n)}</td><td class="fs-12 c-t2">${esc(lbls || 'none')}</td></tr>`;
      }));
    }
    h += section(`Namespaces (${ns.count})`, 'namespaces', c);
  }
  if (sd.services) {
    const sv = sd.services;
    let c = `<div class="inline-stat">${stat(sv.count, 'Services')}</div>`;
    if (sv.services && sv.services.length) {
      c += table([th('Namespace'), th('Name'), th('Type'), th('Ports')], sv.services.map((s) => {
        const ports = (s.ports || []).map((p) => (p.name ? p.name + ':' : '') + p.port + '/' + p.protocol).join(', ');
        return `<tr><td class="mono">${esc(s.namespace)}</td><td class="mono fw-500">${esc(s.name)}</td><td>${esc(s.type)}</td><td class="mono">${esc(ports)}</td></tr>`;
      }));
    }
    h += section(`Services (${sv.count})`, 'services', c);
  }
  if (sd.ingresses) {
    const ig = sd.ingresses;
    let c = `<div class="inline-stat">${stat(ig.count, 'Ingresses')}</div>`;
    if (ig.ingresses && ig.ingresses.length) {
      c += table([th('Namespace'), th('Name'), th('Class'), th('Hosts'), th('TLS')],
        ig.ingresses.map((i) => `<tr><td class="mono">${esc(i.namespace)}</td><td class="mono fw-500">${esc(i.name)}</td><td>${esc(i.ingress_class_name || 'default')}</td>` +
          `<td class="mono">${esc((i.hosts || []).join(', '))}</td><td class="c-${i.tls ? 'ok' : 'warn'}">${i.tls ? 'yes' : 'no'}</td></tr>`));
    }
    h += section(`Ingresses (${ig.count})`, 'ingresses', c);
  }
  if (sd['resource-quotas']) {
    const rq = sd['resource-quotas'];
    let c = `<div class="g g3">${stat(rq.quota_count, 'Quotas')}${stat(rq.limit_range_count, 'Limit ranges')}${stat(rq.namespaces_with_quotas, 'NS with quotas')}</div>`;
    if (rq.quotas && rq.quotas.length) {
      c += table([th('Namespace'), th('Name'), th('Hard limits'), th('Current usage')], rq.quotas.map((q) => {
        const hard = q.hard ? Object.entries(q.hard).map((e) => e[0] + ': ' + e[1]).join(', ') : '';
        const used = q.used ? Object.entries(q.used).map((e) => e[0] + ': ' + e[1]).join(', ') : '';
        return `<tr><td class="mono">${esc(q.namespace)}</td><td class="mono fw-500">${esc(q.name)}</td><td class="fs-12">${esc(hard)}</td><td class="fs-12 c-t2">${esc(used)}</td></tr>`;
      }));
    }
    h += section('Resource Quotas', 'resource-quotas', c);
  }
  if (sd.crds) {
    const cr = sd.crds;
    let c = `<div class="inline-stat">${stat(cr.count, 'CRDs')}</div>`;
    if (cr.crds && cr.crds.length) {
      c += table([th('Name'), th('Group'), th('Versions'), th('Scope', 'Namespaced or Cluster scope')],
        cr.crds.map((x) => `<tr><td class="mono fw-500">${esc(x.name)}</td><td class="mono">${esc(x.group)}</td><td class="mono">${esc((x.versions || []).join(', '))}</td><td>${esc(x.scope)}</td></tr>`));
    }
    h += section(`Custom Resource Definitions (${cr.count})`, 'crds', c);
  }
  return h;
}

on('toggle-section', (btn) => {
  const sec = btn.closest('.dsec');
  sec.classList.toggle('open');
  btn.setAttribute('aria-expanded', String(sec.classList.contains('open')));
});

onChange('filter-events', (input) => {
  const q = input.value.toLowerCase();
  document.querySelectorAll('#evTable tbody tr').forEach((r) => {
    r.classList.toggle('hidden', !!q && r.dataset.evtext.indexOf(q) < 0);
  });
});

on('export-cluster', () => {
  const d = lastDetail;
  if (!d) return;
  const rows = [];
  Object.keys(d.scanner_data || {}).forEach((s) => {
    const data = d.scanner_data[s] || {};
    Object.keys(data).forEach((k) => {
      const v = data[k];
      rows.push([d.cluster, s, k, typeof v === 'object' ? JSON.stringify(v) : v]);
    });
  });
  csvExport('fleetsweeper-' + d.cluster + '.csv', ['Cluster', 'Scanner', 'Field', 'Value'], rows);
});

on('export-events', () => {
  const d = lastDetail;
  if (!d || !d.scanner_data || !d.scanner_data.events) return;
  const rows = (d.scanner_data.events.recent_warnings || []).map((e) => [e.namespace, e.kind, e.involved_object, e.reason, e.message, e.count, e.first_seen, e.last_seen]);
  csvExport('fleetsweeper-events-' + d.cluster + '.csv', ['Namespace', 'Kind', 'Object', 'Reason', 'Message', 'Count', 'First Seen', 'Last Seen'], rows);
});
