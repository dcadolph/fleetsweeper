// The add-cluster page: every kubeconfig context the server can reach, with a
// button to scan it.

import { api } from '../api.js';
import { send } from '../auth.js';
import { esc, byId, emptyState } from '../dom.js';
import { renderBar } from '../shell.js';
import { on } from '../actions.js';
import { openConnect } from '../welcome.js';

let contexts = [];

// renderManage lists the server's kubeconfig contexts, then the
// integrations.
export async function renderManage() {
  return { html: (await contextsSection()) + '<div id="integrationsPanel"></div>', post: loadIntegrationsPanel };
}

// contextsSection renders the contexts the server can reach.
async function contextsSection() {
  renderBar('');
  let h = '<h2>Add clusters</h2><p class="sub">Every context fleetsweeper can reach via its kubeconfig. Click Scan to bring a cluster into the fleet.</p>' +
    '<div class="controls">';
  const controls = '<button class="welcome-btn welcome-btn-ghost" data-action="connect">How do I add clusters?</button><span id="m-status" class="fs-14 c-t2"></span></div>';
  try {
    contexts = await api('/contexts');
  } catch (e) {
    return h + controls + '<div class="manage-empty">Failed to list contexts: ' + esc(e.message) + '</div>';
  }
  if (!contexts || !contexts.length) {
    return h + controls + emptyState('The server has no kubeconfig contexts to scan.',
      'Restart with <code>--kubeconfig /path/to/kubeconfig</code> or set <code>$KUBECONFIG</code>. ' +
      '<button class="welcome-btn welcome-btn-primary" data-action="connect">Show me how</button>');
  }
  h += '<button class="welcome-btn welcome-btn-primary" data-action="scan-contexts" data-all="1">Scan all available</button>' + controls;
  h += '<div class="manage-grid">' + contexts.map((c) => '<div class="manage-card">' +
    `<div class="manage-name">${esc(c.name)}</div><div class="manage-status${c.scanned ? ' scanned' : ''}">${c.scanned ? 'In fleet' : 'Not yet scanned'}</div>` +
    `<div class="manage-actions"><button data-action="scan-contexts" data-context="${esc(c.name)}">${c.scanned ? 'Rescan' : 'Scan now'}</button></div></div>`).join('') + '</div>';
  return h;
}

// scanContexts starts a scan of names and reports progress in the status
// line.
async function scanContexts(names, btn) {
  const status = byId('m-status');
  const label = btn.textContent;
  btn.textContent = 'Scanning...';
  btn.disabled = true;
  if (status) status.textContent = 'Triggering scan of ' + names.length + ' cluster(s)...';
  try {
    const r = await send('POST', '/scans', { contexts: names }, 'Scan');
    if (status) status.textContent = r ? 'Scan running in background. Dashboard will update when it completes.' : '';
  } finally {
    btn.textContent = label;
    btn.disabled = false;
  }
}

on('scan-contexts', (btn) => scanContexts(btn.dataset.all ? contexts.map((c) => c.name) : [btn.dataset.context], btn));
on('connect', () => openConnect());

// loadIntegrationsPanel fills the integrations grid.
function loadIntegrationsPanel() {
  const el = byId('integrationsPanel');
  if (!el) return;
  api('/integrations').then((d) => {
    if (!d || !d.items) return;
    let h = '<h3>Integrations <span class="fs-12 fw-500 c-t3">(configured vs available)</span></h3><div class="g g3">';
    d.items.forEach((it) => {
      const isOn = it.status === 'configured' || it.status === 'demo';
      h += `<div class="cd${isOn ? ' bg-ok' : ''}"><div class="flex between items-center">` +
        `<div class="fs-12 fw-500">${esc(it.name)}</div><span class="fs-12 fw-600 ${isOn ? 'c-ok' : 'c-t3'}">${esc(it.status)}</span></div>` +
        (it.hint ? `<div class="note mt-4">${esc(it.hint)}</div>` : '') + '</div>';
    });
    el.innerHTML = h + '</div>';
  }).catch(() => {});
}
