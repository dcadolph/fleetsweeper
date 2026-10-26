// The add-cluster page: every kubeconfig context the server can reach, with a
// button to scan it.

import { api, apiSend } from '../api.js';
import { esc, byId } from '../dom.js';
import { renderBar } from '../shell.js';
import { on } from '../actions.js';
import { openConnect } from '../welcome.js';

let contexts = [];

// renderManage lists the server's kubeconfig contexts.
export async function renderManage() {
  renderBar('');
  let h = '<h2>Add clusters</h2><p class="sub">Every context fleetsweeper can reach via its kubeconfig. Click Scan to bring a cluster into the fleet.</p>' +
    '<div class="controls"><button class="welcome-btn welcome-btn-primary" data-action="scan-contexts" data-all="1">Scan all available</button>' +
    '<button class="welcome-btn welcome-btn-ghost" data-action="connect">How do I add clusters?</button><span id="m-status" class="fs-14 c-t2"></span></div>';
  try {
    contexts = await api('/contexts');
  } catch (e) {
    return h + '<div class="manage-empty">Failed to list contexts: ' + esc(e.message) + '</div>';
  }
  if (!contexts || !contexts.length) {
    return h + '<div class="manage-empty"><div>No kubeconfig contexts available to the server.</div>' +
      '<div class="fs-14 c-t3 mt-4">Restart with <code>--kubeconfig /path/to/kubeconfig</code> or set <code>$KUBECONFIG</code>.</div>' +
      '<button class="welcome-btn welcome-btn-primary" data-action="connect">Show me how</button></div>';
  }
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
    const r = await apiSend('POST', '/scans', { contexts: names });
    let msg = 'Scan running in background. Dashboard will update when it completes.';
    if (r.status === 401 || r.status === 403) msg = 'Server requires --auth-token or --insecure. See readme.';
    else if (r.status === 429) msg = 'A scan is already in progress. Try again in a moment.';
    else if (!r.ok) msg = 'Scan request failed: ' + r.status;
    if (status) status.textContent = msg;
  } catch (e) {
    if (status) status.textContent = 'Scan request failed: ' + e.message;
  } finally {
    btn.textContent = label;
    btn.disabled = false;
  }
}

on('scan-contexts', (btn) => scanContexts(btn.dataset.all ? contexts.map((c) => c.name) : [btn.dataset.context], btn));
on('connect', () => openConnect());
