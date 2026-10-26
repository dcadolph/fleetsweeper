// The sidebar and the top bar. Both are built from the route table and carry
// only data-action markup; app.js registers what the buttons do.

import { ROUTES } from './routes.js';
import { esc } from './dom.js';
import { paintLive } from './live.js';
import { themeLabel } from './theme.js';

// renderSidebar draws the navigation for the current page.
export function renderSidebar(page) {
  let h = '<a class="sb-brand" href="#/" title="Back to dashboard"><img class="sb-logo" src="logo.jpg" alt=""><h1>Fleetsweeper</h1></a>';
  let group = null;
  ROUTES.filter((r) => r.group).forEach((r) => {
    if (r.group !== group) {
      group = r.group;
      h += `<div class="hd">${esc(group)}</div>`;
    }
    const href = r.id === 'dash' ? '#/' : '#/' + r.id;
    const current = r.id === page || (page === 'detail' && r.id === 'clusters') || (page === 'scanReport' && r.id === 'scans');
    h += `<a class="sb-link${current ? ' on' : ''}" href="${href}" title="${esc(r.label)}"${current ? ' aria-current="page"' : ''}>` +
      `<span class="sb-abbr" aria-hidden="true">${esc(r.abbr)}</span><span class="sb-label">${esc(r.label)}</span></a>`;
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
    '<button id="live-toggle" class="live-toggle" data-action="live-toggle"><span class="live-dot"></span><span>Live · paused</span></button>' +
    '<button class="tour-launcher" data-action="tour-start">Take a tour</button>' +
    `<button class="btn" data-action="theme" id="theme-toggle">${esc(themeLabel())}</button>` +
    '<button class="btn" data-action="shortcuts" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">?</button>';
  document.getElementById('bar').innerHTML = h;
  paintLive();
}
