// Hash routing. The URL hash is the only source of the current page and its
// filters: nav() writes it, and one hashchange listener renders, so a deep
// link, a reload, back and forward, and an in-app click all take the same
// path and the page renders once. A query after the path, as in
// #/findings?cluster=a&scanner=b, carries a page's filters in P.query.
// refresh() re-renders the current page in place for live updates.

import { ROUTES, routeById } from './routes.js';
import { destroyCharts, themeCharts } from './charts.js';
import { renderSidebar, refreshBadges } from './shell.js';
import { esc } from './dom.js';
import { morph } from './morph.js';

// P is the current page state. query holds the hash's query parameters.
export const P = { page: 'dash', cluster: null, scanId: null, diffA: null, diffB: null, query: {} };

const leaveHooks = [];

// onLeave registers fn to run once before the next render, for views that
// own timers or listeners.
export function onLeave(fn) {
  leaveHooks.push(fn);
}

// queryString returns "?a=1&b=2" for the non-empty entries of query, or "".
function queryString(query) {
  const q = new URLSearchParams();
  Object.keys(query || {}).sort().forEach((k) => {
    if (query[k] !== undefined && query[k] !== null && query[k] !== '') q.set(k, query[k]);
  });
  const s = q.toString();
  return s ? '?' + s : '';
}

// hashFor returns the hash of a page and its options. opts.query adds query
// parameters.
export function hashFor(page, opts) {
  const o = opts || {};
  const q = queryString(o.query);
  if (page === 'dash') return '#/' + q;
  if (page === 'detail' && o.cluster) return '#/cluster/' + encodeURIComponent(o.cluster) + q;
  if (page === 'scanReport' && o.scanId) return '#/scan/' + encodeURIComponent(o.scanId) + q;
  return '#/' + page + q;
}

// setQuery replaces the current page's query parameters in the URL without
// rendering, so a reload or a shared link keeps the filters.
export function setQuery(query) {
  P.query = { ...query };
  const hash = hashFor(P.page, { cluster: P.cluster, scanId: P.scanId, query: P.query });
  if (location.hash !== hash) history.replaceState(null, '', hash);
}

// stateFromHash parses the current hash into a page and its options.
export function stateFromHash() {
  const raw = (location.hash || '#/').replace(/^#\/?/, '');
  const at = raw.indexOf('?');
  const path = at < 0 ? raw : raw.slice(0, at);
  const query = Object.fromEntries(new URLSearchParams(at < 0 ? '' : raw.slice(at + 1)));
  const parts = path.split('/');
  if (parts[0] === 'cluster' && parts[1]) return { page: 'detail', cluster: decodeURIComponent(parts[1]), query };
  if (parts[0] === 'scan' && parts[1]) return { page: 'scanReport', scanId: decodeURIComponent(parts[1]), query };
  const known = ROUTES.some((r) => r.id === parts[0]);
  return { page: known ? parts[0] : 'dash', query };
}

// nav moves to a page. When the hash does not change, the page re-renders in
// place.
export function nav(page, opts) {
  const hash = hashFor(page, opts);
  if (decodeURIComponent(location.hash) === decodeURIComponent(hash) || (hash === '#/' && (location.hash === '' || location.hash === '#'))) {
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
  P.query = s.query || {};
}

// runLeaveHooks runs and clears the hooks registered with onLeave.
function runLeaveHooks() {
  while (leaveHooks.length) {
    try { leaveHooks.shift()(); } catch (_) { /* a failing hook must not block the next page */ }
  }
}

// render draws the current page into #ct.
export async function render() {
  destroyCharts();
  themeCharts();
  runLeaveHooks();
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

// refresh re-renders the current page in place: the view fetches its data
// again and the result is morphed into the page, so scroll, filters, open
// sections, and focus survive. A failed refresh leaves the page as it was.
export async function refresh() {
  const page = P.page;
  const el = document.getElementById('ct');
  let result;
  try {
    result = await routeById(page).render();
  } catch (_) {
    return;
  }
  if (P.page !== page) return;
  destroyCharts();
  themeCharts();
  runLeaveHooks();
  renderSidebar(P.page);
  refreshBadges();
  if (typeof result === 'string') {
    morph(el, result);
  } else if (result) {
    morph(el, result.html);
    if (result.post) await result.post();
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
