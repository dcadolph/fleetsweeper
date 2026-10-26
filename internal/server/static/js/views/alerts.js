// The alerts page: runtime alerts ingested from AlertManager and Falco.

import { api, apiSend } from '../api.js';
import { esc, sevTone, byId } from '../dom.js';
import { renderBar } from '../shell.js';
import { render } from '../router.js';
import { on, onChange, onDblClick } from '../actions.js';

let alerts = [];

// sourceOf names the system an alert came from.
function sourceOf(a) {
  return (a.labels && a.labels.source) || (a.labels && a.labels.k8s_cluster_name ? 'falco' : 'alertmanager');
}

// renderAlerts lists the most recent alerts with source and severity filters.
export async function renderAlerts() {
  renderBar('<select id="aSrc" data-change="filter-alerts" aria-label="Source"><option value="">All sources</option><option value="alertmanager">AlertManager</option><option value="falco">Falco</option></select> ' +
    '<select id="aSev" data-change="filter-alerts" aria-label="Severity"><option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>');
  let resp;
  try {
    resp = await api('/alerts?limit=200');
  } catch (e) {
    return '<div class="loading">Alerts unavailable: ' + esc(e.message) + '</div>';
  }
  alerts = (resp && resp.alerts) || [];
  const h = '<h2>Inbound alerts</h2>' +
    '<p class="sub">Live runtime alerts ingested from AlertManager and Falco. Filter, then double-click a row to see the full label set.</p>' +
    '<div class="tw"><table id="alertsTable"><thead><tr><th>When</th><th>Severity</th><th>Source</th><th>Cluster</th><th>Alert</th><th>Summary</th><th></th></tr></thead><tbody id="alertsBody"></tbody></table></div>';
  return { html: h, post: filterAlerts };
}

// filterAlerts redraws the alert rows matching the filters.
function filterAlerts() {
  const tb = byId('alertsBody');
  if (!tb) return;
  const src = (byId('aSrc') || {}).value || '';
  const sev = (byId('aSev') || {}).value || '';
  const rows = alerts.map((a, i) => ({ a, i })).filter(({ a }) => (!src || sourceOf(a) === src) && (!sev || a.severity === sev));
  tb.innerHTML = rows.length ? rows.map(({ a, i }) => {
    const tone = a.severity === 'critical' || a.severity === 'warning' ? sevTone(a.severity) : 'ok';
    return `<tr data-dblclick="alert-labels" data-i="${i}" title="Double-click for labels"><td>${esc(a.received_at ? new Date(a.received_at).toLocaleString() : '')}</td>` +
      `<td class="c-${tone}">${esc(a.severity || '')}</td><td>${esc(sourceOf(a))}</td><td>${esc(a.cluster || '')}</td><td>${esc(a.alertname || '')}</td>` +
      `<td>${esc(a.summary || '')}</td><td><button class="btn" data-action="ack-alert" data-fp="${esc(a.fingerprint)}">Ack</button></td></tr>`;
  }).join('') : '<tr><td colspan="7" class="empty">No alerts match the current filters.</td></tr>';
}

onChange('filter-alerts', filterAlerts);

onDblClick('alert-labels', (row) => {
  const a = alerts[Number(row.dataset.i)];
  if (a) window.alert(JSON.stringify(a.labels || {}, null, 2));
});

on('ack-alert', async (btn) => {
  const reason = window.prompt('Reason (optional):', '') || '';
  try {
    const r = await apiSend('POST', '/alerts/' + encodeURIComponent(btn.dataset.fp) + '/ack', { reason, ack_by: 'dashboard' });
    if (!r.ok) {
      window.alert('Ack failed: ' + r.status + ' ' + r.statusText);
      return;
    }
    render();
  } catch (e) {
    window.alert('Ack error: ' + e.message);
  }
});
