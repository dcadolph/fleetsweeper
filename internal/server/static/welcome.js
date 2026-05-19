// Welcome splash and connect-your-cluster modal. Shown in demo mode on
// first visit; reachable from the top-bar Help menu afterward.

(function () {
  'use strict';

  function maybeShow() {
    // In demo mode we want the splash to greet operators on every fresh load
    // so the cinematic experience is always one click away. Suppress it only
    // when the URL points at a specific page already (a Slack-pasted deep
    // link should drop you straight into that page).
    var deepLink = location.hash && location.hash !== '#/' && location.hash !== '#';
    if (deepLink) return;
    fetchDemoState(function (isDemo, points) {
      if (!isDemo) return;
      showWelcome(points);
    });
  }

  function fetchDemoState(cb) {
    fetch('/api/geo')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) { cb(false, 0); return; }
        cb(!!d.demo, (d.points || []).length);
      })
      .catch(function () { cb(false, 0); });
  }

  function showWelcome(points) {
    var root = document.createElement('div');
    root.className = 'welcome-root';
    root.id = 'welcome-root';
    root.innerHTML =
      '<img class="welcome-logo" src="logo.jpg" alt="fleetsweeper">' +
      '<div class="welcome-badge">Demo mode &nbsp;·&nbsp; Synthetic fleet</div>' +
      '<h1>See if your fleet has drifted.</h1>' +
      '<p class="welcome-sub">' +
      'Every other Kubernetes tool tells you if one cluster is healthy. Fleetsweeper compares your clusters against each other and surfaces what is anomalous. You are looking at a synthetic fleet so you can explore the whole UI without any real clusters.' +
      '</p>' +
      '<div class="welcome-actions">' +
      '  <button class="welcome-btn welcome-btn-primary" data-w-act="tour">Take the cinematic tour</button>' +
      '  <button class="welcome-btn welcome-btn-ghost" data-w-act="explore">Explore on my own</button>' +
      '  <button class="welcome-btn welcome-btn-ghost" data-w-act="connect">Connect my own clusters</button>' +
      '</div>' +
      '<div class="welcome-stats">' +
      '  <div><strong>' + points + '</strong>Clusters in this fleet</div>' +
      '  <div><strong>4</strong>Continents</div>' +
      '  <div><strong>16</strong>Scanners running</div>' +
      '  <div><strong>0</strong>Agents installed</div>' +
      '</div>';
    document.body.appendChild(root);
    document.body.style.overflow = 'hidden';

    root.querySelectorAll('[data-w-act]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var act = btn.getAttribute('data-w-act');
        dismiss();
        if (act === 'tour' && window.Tour) {
          setTimeout(function () { window.Tour.start(); }, 200);
        } else if (act === 'connect' && window.ConnectModal) {
          window.ConnectModal.open();
        }
      });
    });
  }

  function dismiss() {
    var root = document.getElementById('welcome-root');
    if (root) root.remove();
    document.body.style.overflow = '';
  }

  window.Welcome = { show: maybeShow };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', maybeShow);
  } else {
    maybeShow();
  }
})();

// Connect-your-cluster modal. Pure instructions; no backend change.
(function () {
  'use strict';

  function open() {
    if (document.getElementById('connect-modal')) return;
    var root = document.createElement('div');
    root.className = 'modal-root';
    root.id = 'connect-modal';
    root.innerHTML =
      '<div class="modal-card">' +
      '  <h3>Connect your own clusters</h3>' +
      '  <p class="modal-sub">Fleetsweeper is agentless. Point it at a kubeconfig with one or more contexts and you are done.</p>' +
      '  <h4>1. Run against your local kubeconfig</h4>' +
      '  <pre>fleetsweeper serve --addr :8080 \\\n  --auth-token "$(openssl rand -hex 32)"</pre>' +
      '  <p>The server reads <code>$KUBECONFIG</code> (or <code>~/.kube/config</code>). Hit the Clusters page to see every context it can scan, then click Scan on the ones you want to bring into the fleet.</p>' +
      '  <h4>2. Or pass a specific kubeconfig</h4>' +
      '  <pre>fleetsweeper serve --kubeconfig /etc/fleetsweeper/kubeconfig \\\n  --db /var/lib/fleetsweeper/fleet.db \\\n  --auth-token "$TOKEN"</pre>' +
      '  <h4>3. Or deploy inside a cluster</h4>' +
      '  <pre>helm install fleetsweeper deploy/helm/fleetsweeper \\\n  --namespace fleetsweeper --create-namespace \\\n  --set auth.token="$(openssl rand -hex 32)"</pre>' +
      '  <p>The chart includes a least-privilege ClusterRole and ServiceAccount. Fleetsweeper reads cluster state only; it never writes.</p>' +
      '  <div class="modal-actions">' +
      '    <button class="tour-btn tour-btn-ghost" data-c-act="close">Close</button>' +
      '    <button class="tour-btn tour-btn-primary" data-c-act="manage">Open Clusters page</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(root);

    root.addEventListener('click', function (e) {
      if (e.target === root) close();
    });
    root.querySelectorAll('[data-c-act]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var a = btn.getAttribute('data-c-act');
        close();
        if (a === 'manage' && window.nav) {
          window.nav('manage');
        }
      });
    });
  }

  function close() {
    var root = document.getElementById('connect-modal');
    if (root) root.remove();
  }

  window.ConnectModal = { open: open, close: close };
})();
