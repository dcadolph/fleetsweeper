// Add-cluster page. Lists every kubeconfig context available to the server
// and lets the operator trigger a scan against it. Demo mode shows the
// synthetic fleet's contexts so the page is not empty.

(function () {
  'use strict';

  async function renderManage() {
    if (typeof window.renderBar === 'function') window.renderBar('');
    var ct = document.getElementById('ct');
    ct.innerHTML =
      '<h2>Add clusters</h2>' +
      '<p class="sub">Every context fleetsweeper can reach via its kubeconfig. Click Scan to bring a cluster into the fleet.</p>' +
      '<div style="display:flex;gap:10px;margin:14px 0;align-items:center;flex-wrap:wrap;">' +
      '  <button class="welcome-btn welcome-btn-primary" id="m-scan-all" style="padding:8px 16px;font-size:13px;border-radius:7px;">Scan all available</button>' +
      '  <button class="welcome-btn welcome-btn-ghost" id="m-connect" style="padding:8px 16px;font-size:13px;border-radius:7px;">How do I add clusters?</button>' +
      '  <span id="m-status" style="color:var(--t2);font-size:13px;"></span>' +
      '</div>' +
      '<div id="m-grid" class="manage-grid"></div>';

    var grid = document.getElementById('m-grid');
    var status = document.getElementById('m-status');

    try {
      var contexts = await fetch('/api/contexts').then(function (r) { return r.json(); });
      if (!contexts || contexts.length === 0) {
        grid.outerHTML =
          '<div class="manage-empty">' +
          '  <div>No kubeconfig contexts available to the server.</div>' +
          '  <div style="margin-top:6px;font-size:13px;color:var(--t3);">Restart with <code>--kubeconfig /path/to/kubeconfig</code> or set <code>$KUBECONFIG</code>.</div>' +
          '  <button class="welcome-btn welcome-btn-primary" style="padding:8px 16px;font-size:13px;border-radius:7px;" id="m-empty-connect">Show me how</button>' +
          '</div>';
        var b = document.getElementById('m-empty-connect');
        if (b && window.ConnectModal) b.addEventListener('click', window.ConnectModal.open);
        return;
      }
      grid.innerHTML = contexts.map(renderCard).join('');
      grid.querySelectorAll('[data-m-scan]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var ctx = btn.getAttribute('data-m-scan');
          triggerScan([ctx], status, btn);
        });
      });
      var scanAll = document.getElementById('m-scan-all');
      if (scanAll) {
        scanAll.addEventListener('click', function () {
          var names = contexts.map(function (c) { return c.name; });
          triggerScan(names, status, scanAll);
        });
      }
      var connect = document.getElementById('m-connect');
      if (connect && window.ConnectModal) {
        connect.addEventListener('click', window.ConnectModal.open);
      }
    } catch (e) {
      grid.innerHTML =
        '<div class="manage-empty">Failed to list contexts: ' + escapeHTML(e.message) + '</div>';
    }
  }

  function renderCard(c) {
    var statusText = c.scanned ? 'In fleet' : 'Not yet scanned';
    var statusClass = c.scanned ? 'manage-status scanned' : 'manage-status';
    return (
      '<div class="manage-card">' +
      '  <div class="manage-name">' + escapeHTML(c.name) + '</div>' +
      '  <div class="' + statusClass + '">' + statusText + '</div>' +
      '  <div class="manage-actions">' +
      '    <button data-m-scan="' + escapeHTML(c.name) + '">' + (c.scanned ? 'Rescan' : 'Scan now') + '</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function triggerScan(contexts, statusEl, btn) {
    var label = btn ? btn.textContent : '';
    if (btn) { btn.textContent = 'Scanning...'; btn.disabled = true; }
    if (statusEl) statusEl.textContent = 'Triggering scan of ' + contexts.length + ' cluster(s)...';
    var headers = { 'Content-Type': 'application/json' };
    var auth = window._authToken;
    if (auth) headers['Authorization'] = 'Bearer ' + auth;
    fetch('/api/scans', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ contexts: contexts }),
    }).then(function (r) {
      if (r.status === 403) {
        if (statusEl) statusEl.textContent = 'Server requires --auth-token or --insecure. See readme.';
      } else if (r.status === 429) {
        if (statusEl) statusEl.textContent = 'A scan is already in progress. Try again in a moment.';
      } else if (!r.ok) {
        if (statusEl) statusEl.textContent = 'Scan request failed: ' + r.status;
      } else {
        if (statusEl) statusEl.textContent = 'Scan running in background. Dashboard will update when it completes.';
      }
    }).catch(function (e) {
      if (statusEl) statusEl.textContent = 'Scan request failed: ' + e.message;
    }).finally(function () {
      if (btn) { btn.textContent = label; btn.disabled = false; }
    });
  }

  function escapeHTML(s) {
    var d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  window.renderManage = renderManage;
})();
