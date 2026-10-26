// The alerts page: runtime alerts ingested from AlertManager and Falco, as
// finding cards with their labels folded away and the same ack drawer.

import { api } from '../api.js';
import { esc, byId } from '../dom.js';
import { morph } from '../morph.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { onChange } from '../actions.js';

let alerts = [];

// sourceOf names the system an alert came from.
function sourceOf(a) {
  return (a.labels && a.labels.source) || (a.labels && a.labels.k8s_cluster_name ? 'falco' : 'alertmanager');
}

// asFinding maps an alert onto the finding card's fields.
export function asFinding(a) {
  return {
    kind: 'alert',
    title: a.alertname || 'Unnamed alert',
    description: a.summary || '',
    severity: ['critical', 'warning', 'info'].includes(a.severity) ? a.severity : 'info',
    cluster: a.cluster || 'fleet',
    scanner: sourceOf(a) + (a.status ? ' ' + a.status : ''),
    fingerprint: a.fingerprint,
    acked: !!a.acked,
    when: a.received_at ? new Date(a.received_at).toLocaleString() : '',
    labels: a.labels || {},
  };
}

// renderAlerts lists the most recent alerts with source and severity filters.
export async function renderAlerts() {
  renderBar('<select id="aSrc" data-change="filter-alerts" aria-label="Source"><option value="">All sources</option><option value="alertmanager">AlertManager</option><option value="falco">Falco</option></select> ' +
    '<select id="aSev" data-change="filter-alerts" aria-label="Severity"><option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>');
  let resp;
  try {
    resp = await api('/alerts?limit=200');
  } catch (e) {
    return '<div class="empty">Alerts unavailable: ' + esc(e.message) + '</div>';
  }
  alerts = (resp && resp.alerts) || [];
  const h = '<h2>Inbound alerts</h2>' +
    '<p class="sub">Live runtime alerts ingested from AlertManager and Falco, newest first. Open Labels on a card for the full label set.</p>' +
    '<div id="alertsList"></div>';
  return { html: h, post: filterAlerts };
}

// filterAlerts redraws the alert cards matching the filters.
function filterAlerts() {
  const list = byId('alertsList');
  if (!list) return;
  const src = (byId('aSrc') || {}).value || '';
  const sev = (byId('aSev') || {}).value || '';
  const shown = alerts.filter((a) => (!src || sourceOf(a) === src) && (!sev || a.severity === sev));
  morph(list, shown.length ? shown.map((a) => renderFinding(asFinding(a))).join('') : '<div class="empty">No alerts match the current filters.</div>');
}

onChange('filter-alerts', filterAlerts);
