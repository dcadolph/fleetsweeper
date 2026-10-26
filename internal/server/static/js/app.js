// Dashboard entry point. Wires the delegated event handlers, the tooltip, the
// theme, and the global actions, then starts the router.

import { installActions, on } from './actions.js';
import { startRouter } from './router.js';
import { applyTheme, cycleTheme, themeLabel } from './theme.js';
import { loadScannerCatalog } from './api.js';
import { copyText, byId } from './dom.js';
import { toggleLive } from './live.js';
import { startTour } from './tour.js';
import { toggleShortcuts } from './shortcuts.js';
import { openHelpMenu } from './help.js';
import { maybeShowWelcome } from './welcome.js';
import { installDemoEnrichment } from './demo_enrich.js';
import './palette.js';

// installTooltip shows the data-tip of the element under the pointer or with
// keyboard focus, kept inside the viewport.
function installTooltip() {
  const el = byId('tip-el');
  let timer = null;
  const show = (t) => {
    clearTimeout(timer);
    el.textContent = t.dataset.tip;
    el.style.display = 'block';
    const r = t.getBoundingClientRect();
    let left = r.left + r.width / 2 - el.offsetWidth / 2;
    let top = r.top - el.offsetHeight - 8;
    left = Math.max(8, Math.min(left, window.innerWidth - el.offsetWidth - 8));
    if (top < 8) top = r.bottom + 8;
    el.style.left = left + 'px';
    el.style.top = top + 'px';
  };
  const hide = () => { timer = setTimeout(() => { el.style.display = 'none'; }, 80); };
  const target = (e) => e.target.closest && e.target.closest('[data-tip]');
  document.addEventListener('mouseover', (e) => { const t = target(e); if (t && t.dataset.tip) show(t); });
  document.addEventListener('mouseout', (e) => { if (target(e)) hide(); });
  document.addEventListener('focusin', (e) => { const t = target(e); if (t && t.dataset.tip) show(t); });
  document.addEventListener('focusout', (e) => { if (target(e)) hide(); });
}

on('copy', async (btn, ev) => {
  ev.preventDefault();
  ev.stopPropagation();
  const label = btn.textContent;
  try {
    await copyText(btn.dataset.copy || '');
    btn.textContent = 'Copied';
  } catch (_) {
    btn.textContent = 'Copy failed';
  }
  setTimeout(() => { btn.textContent = label; }, 1200);
});
on('clear', (btn) => {
  const target = byId(btn.dataset.target);
  if (target) target.innerHTML = '';
});
on('menu', () => document.body.classList.toggle('nav-open'));
on('live-toggle', () => toggleLive());
on('tour-start', () => startTour());
on('shortcuts', () => toggleShortcuts());
on('help-menu', () => openHelpMenu());
on('theme', (btn) => {
  cycleTheme();
  btn.textContent = themeLabel();
  startRouterRender();
});

// startRouterRender re-renders the page so canvases pick up the new theme.
function startRouterRender() {
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}

applyTheme();
installActions();
installTooltip();
await Promise.all([loadScannerCatalog(), installDemoEnrichment()]);
startRouter();
maybeShowWelcome();
