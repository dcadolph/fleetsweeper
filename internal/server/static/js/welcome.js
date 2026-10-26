// The demo welcome splash and the connect-your-cluster modal.

import { api } from './api.js';
import { esc } from './dom.js';
import { nav } from './router.js';
import { startTour } from './tour.js';

// DISMISSED_KEY is the localStorage key that remembers the viewer closed the
// splash.
const DISMISSED_KEY = 'fleetsweeper-welcome-dismissed';

// dismissed reports whether this viewer closed the splash before.
function dismissed() {
  try {
    return localStorage.getItem(DISMISSED_KEY) === '1';
  } catch (_) {
    return false;
  }
}

// maybeShowWelcome greets a demo visitor arriving without a deep link, once.
// Every number on it comes from the server.
export async function maybeShowWelcome() {
  if (location.hash && location.hash !== '#/' && location.hash !== '#') return;
  if (dismissed()) return;
  let geo;
  let scanners;
  try {
    const integrations = await api('/integrations');
    const demo = (integrations.items || []).some((it) => it.name === 'Demo mode' && it.status === 'demo');
    if (!demo) return;
    [geo, scanners] = await Promise.all([api('/geo'), api('/scanners')]);
  } catch (_) {
    return;
  }
  const root = document.createElement('div');
  root.className = 'welcome-root';
  root.id = 'welcome-root';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.setAttribute('aria-label', 'Welcome');
  root.innerHTML = '<img class="welcome-logo" src="logo.jpg" alt="fleetsweeper">' +
    '<div class="welcome-badge">Demo mode &nbsp;·&nbsp; Synthetic fleet</div>' +
    '<h1>See if your fleet has drifted.</h1>' +
    '<p class="welcome-sub">Every other Kubernetes tool tells you if one cluster is healthy. Fleetsweeper compares your clusters against each other and surfaces what is anomalous. You are looking at a synthetic fleet so you can explore the whole UI without any real clusters.</p>' +
    '<div class="welcome-actions"><button class="welcome-btn welcome-btn-primary" data-w-act="tour">Take the cinematic tour</button>' +
    '<button class="welcome-btn welcome-btn-ghost" data-w-act="explore">Explore on my own</button>' +
    '<button class="welcome-btn welcome-btn-ghost" data-w-act="connect">Connect my own clusters</button></div>' +
    `<div class="welcome-stats"><div><strong>${esc((geo.points || []).length + (geo.unlocated || []).length)}</strong>Clusters in this fleet</div>` +
    `<div><strong>${esc((scanners || []).length)}</strong>Scanners running</div><div><strong>0</strong>Agents installed</div></div>`;
  document.body.appendChild(root);
  document.body.classList.add('modal-open');
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-w-act]');
    if (!btn) return;
    root.remove();
    document.body.classList.remove('modal-open');
    try {
      localStorage.setItem(DISMISSED_KEY, '1');
    } catch (_) { /* the splash shows again next visit */ }
    if (btn.dataset.wAct === 'tour') setTimeout(startTour, 200);
    else if (btn.dataset.wAct === 'connect') openConnect();
  });
}

// openConnect shows the instructions for pointing fleetsweeper at real
// clusters.
export function openConnect() {
  if (document.getElementById('connect-modal')) return;
  const root = document.createElement('div');
  root.className = 'modal-root';
  root.id = 'connect-modal';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.innerHTML = '<div class="modal-card"><h3>Connect your own clusters</h3>' +
    '<p class="modal-sub">Fleetsweeper is agentless. Point it at a kubeconfig with one or more contexts and you are done.</p>' +
    '<h4>1. Run against your local kubeconfig</h4><pre>fleetsweeper serve --addr :8080 \\\n  --auth-token "$(openssl rand -hex 32)"</pre>' +
    '<p>The server reads <code>$KUBECONFIG</code> (or <code>~/.kube/config</code>). Hit the Clusters page to see every context it can scan, then click Scan on the ones you want to bring into the fleet.</p>' +
    '<h4>2. Or pass a specific kubeconfig</h4><pre>fleetsweeper serve --kubeconfig /etc/fleetsweeper/kubeconfig \\\n  --db /var/lib/fleetsweeper/fleet.db \\\n  --auth-token "$TOKEN"</pre>' +
    '<h4>3. Or deploy inside a cluster</h4><pre>helm install fleetsweeper deploy/helm/fleetsweeper \\\n  --namespace fleetsweeper --create-namespace \\\n  --set auth.token="$(openssl rand -hex 32)"</pre>' +
    '<p>The chart includes a least-privilege ClusterRole and ServiceAccount. Fleetsweeper reads cluster state only; it never writes.</p>' +
    '<div class="modal-actions"><button class="tour-btn tour-btn-ghost" data-c-act="close">Close</button><button class="tour-btn tour-btn-primary" data-c-act="manage">Open Clusters page</button></div></div>';
  document.body.appendChild(root);
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-c-act]');
    if (e.target !== root && !btn) return;
    root.remove();
    if (btn && btn.dataset.cAct === 'manage') nav('manage');
  });
}
