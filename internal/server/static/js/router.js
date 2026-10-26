// Hash routing. The URL hash is the only source of the current page: nav()
// writes it, and one hashchange listener renders, so a deep link, a reload,
// back and forward, and an in-app click all take the same path and the page
// renders once.

import { ROUTES, routeById } from './routes.js';
import { destroyCharts, themeCharts } from './charts.js';
import { renderSidebar, refreshBadges } from './shell.js';
import { esc } from './dom.js';

// P is the current page state.
export const P = { page: 'dash', cluster: null, scanId: null, diffA: null, diffB: null, findingsQuery: '', findingsSeverity: '' };

const leaveHooks = [];

// onLeave registers fn to run once before the next render, for views that
// own timers or listeners.
export function onLeave(fn) {
  leaveHooks.push(fn);
}

// hashFor returns the hash of a page and its options.
export function hashFor(page, opts) {
  const o = opts || {};
  if (page === 'dash') return '#/';
  if (page === 'detail' && o.cluster) return '#/cluster/' + encodeURIComponent(o.cluster);
  if (page === 'scanReport' && o.scanId) return '#/scan/' + encodeURIComponent(o.scanId);
  return '#/' + page;
}

// stateFromHash parses the current hash into a page and its options.
function stateFromHash() {
  const h = (location.hash || '#/').replace(/^#\/?/, '');
  const parts = h.split('/');
  if (parts[0] === 'cluster' && parts[1]) return { page: 'detail', cluster: decodeURIComponent(parts[1]) };
  if (parts[0] === 'scan' && parts[1]) return { page: 'scanReport', scanId: decodeURIComponent(parts[1]) };
  const known = ROUTES.some((r) => r.id === parts[0]);
  return { page: known ? parts[0] : 'dash' };
}

// nav moves to a page. When the hash does not change, the page re-renders in
// place.
export function nav(page, opts) {
  const hash = hashFor(page, opts);
  if (location.hash === hash || (hash === '#/' && (location.hash === '' || location.hash === '#'))) {
    applyState({ page, ...(opts || {}) });
    render();
    return;
  }
  location.hash = hash;
}

// applyState copies a parsed state into P.
function applyState(s) {
  P.page = s.page;
  P.cluster = s.cluster || null;
  P.scanId = s.scanId || null;
}

// render draws the current page into #ct.
export async function render() {
  destroyCharts();
  themeCharts();
  while (leaveHooks.length) {
    try { leaveHooks.shift()(); } catch (_) { /* a failing hook must not block the next page */ }
  }
  renderSidebar(P.page);
  refreshBadges();
  document.body.classList.remove('nav-open');
  const el = document.getElementById('ct');
  el.innerHTML = '<div class="loading">Loading...</div>';
  const page = P.page;
  try {
    const result = await routeById(page).render();
    if (P.page !== page) return;
    if (typeof result === 'string') {
      el.innerHTML = result;
    } else if (result) {
      el.innerHTML = result.html;
      if (result.post) await result.post();
    }
  } catch (e) {
    el.innerHTML = '<div class="empty">Error: ' + esc(e.message) + '</div>';
  }
}

// startRouter renders the page the URL names and follows hash changes.
export function startRouter() {
  window.addEventListener('hashchange', () => {
    applyState(stateFromHash());
    render();
  });
  applyState(stateFromHash());
  render();
}
