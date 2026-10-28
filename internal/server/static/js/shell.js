// The sidebar and the top bar. Both are built from the route table and carry
// only data-action markup; app.js registers what the buttons do.

import { ROUTES } from './routes.js';
import { api } from './api.js';
import { esc } from './dom.js';
import { paintLive } from './live.js';
import { hasToken } from './auth.js';
import { morph } from './morph.js';
import { themeLabel } from './theme.js';

// badges maps a route id to the count shown beside it, and badgeScan is the
// scan the counts came from.
const badges = {};
let badgeScan = null;

// setBadge sets the count shown beside a route, zero to hide it, and repaints
// that link in place.
export function setBadge(id, count, label) {
  badges[id] = { count, label };
  const link = document.querySelector(`.sb-link[data-route="${id}"]`);
  if (!link) return;
  const old = link.querySelector('.sb-badge');
  if (old) old.remove();
  if (count > 0) link.insertAdjacentHTML('beforeend', badgeHTML(badges[id]));
}

// badgeHTML returns the markup of one badge.
function badgeHTML(b) {
  return `<span class="sb-badge" data-tip="${esc(b.label)}" aria-label="${esc(b.label)}">${b.count}</span>`;
}

// noteCriticalCount sets the Findings badge from a report the caller already
// has, so a page that fetched the report does not fetch it again.
export function noteCriticalCount(scanId, findings) {
  badgeScan = scanId;
  const n = (findings || []).filter((f) => f.severity === 'critical').length;
  setBadge('findings', n, n + ' critical finding' + (n === 1 ? '' : 's') + ' in the latest scan');
}

// refreshBadges reads the latest scan and, when it changed since the last
// count, recounts its critical findings. Failures leave the badge as it was.
export async function refreshBadges() {
  try {
    const scans = await api('/scans?limit=1');
    if (!scans || !scans.length || scans[0].id === badgeScan) return;
    const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
    noteCriticalCount(scans[0].id, rpt.findings);
  } catch (_) { /* the badge is a convenience */ }
}

// renderSidebar draws the navigation for the current page.
export function renderSidebar(page) {
  let h = '<a class="sb-brand" href="#/" title="Back to dashboard"><img class="sb-logo" src="logo.svg" alt=""><h1>Fleetsweeper</h1></a>';
  let group = null;
  ROUTES.filter((r) => r.group).forEach((r) => {
    if (r.group !== group) {
      group = r.group;
      h += `<div class="hd">${esc(group)}</div>`;
    }
    const href = r.id === 'dash' ? '#/' : '#/' + r.id;
    const current = r.id === page || (page === 'detail' && r.id === 'clusters') || (page === 'scanReport' && r.id === 'scans');
    const badge = badges[r.id] && badges[r.id].count > 0 ? badgeHTML(badges[r.id]) : '';
    h += `<a class="sb-link${current ? ' on' : ''}" href="${href}" data-route="${r.id}" title="${esc(r.label)}"${current ? ' aria-current="page"' : ''}>` +
      `<span class="sb-abbr" aria-hidden="true">${esc(r.abbr)}</span><span class="sb-label">${esc(r.label)}</span>${badge}</a>`;
  });
  h += '<div class="sb-help"><div class="hd">Help</div>' +
    '<button class="sb-link" data-action="help-menu"><span class="sb-abbr" aria-hidden="true">?</span><span class="sb-label">How it works</span></button>' +
    '<a class="sb-link" href="/cinematic" target="_blank" rel="noopener"><span class="sb-abbr" aria-hidden="true">Ci</span><span class="sb-label">Watch the cinematic</span></a></div>';
  document.getElementById('sb').innerHTML = h;
}

// renderBar draws the top bar with optional page-specific controls before the
// global ones.
export function renderBar(extra) {
  const h = '<button class="btn menu-btn" data-action="menu" aria-label="Open navigation">Menu</button>' +
    (extra || '') +
    '<span class="sp"></span>' +
    '<button id="live-toggle" class="live-toggle" data-action="live-toggle"><span class="live-dot" aria-hidden="true"></span><span>Live · paused</span></button>' +
    '<button class="tour-launcher" data-action="tour-start">Take a tour</button>' +
    `<button class="btn" data-action="token" id="token-btn" data-tip="API token for acknowledging findings and starting scans">${hasToken() ? 'Token set' : 'Token'}</button>` +
    `<button class="btn" data-action="theme" id="theme-toggle">${esc(themeLabel())}</button>` +
    '<button class="btn" data-action="shortcuts" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">?</button>';
  morph(document.getElementById('bar'), h);
  paintLive();
}

// paintToken updates the token button after the token changes.
export function paintToken(has) {
  const btn = document.getElementById('token-btn');
  if (btn) btn.textContent = has ? 'Token set' : 'Token';
}
