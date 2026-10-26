// Keyboard shortcuts: the ? overlay, g-chords built from the route table,
// and single-key toggles.

import { ROUTES } from './routes.js';
import { nav } from './router.js';
import { esc } from './dom.js';
import { toggleLive } from './live.js';
import { startTour } from './tour.js';
import { openModal } from './components/modal.js';

// chordRoutes lists the routes reachable with g followed by a key.
const chordRoutes = ROUTES.filter((r) => r.chord);

// groups describes the overlay's sections.
function groups() {
  return [
    { group: 'Navigation', items: [{ keys: ['Cmd', 'K'], label: 'Open command palette (clusters, pages)' }]
      .concat(chordRoutes.map((r) => ({ keys: ['g', r.chord], label: 'Go to ' + r.label }))) },
    { group: 'Findings page', items: [{ keys: ['/'], label: 'Focus the filter input' }] },
    { group: 'Live & tour', items: [{ keys: ['l'], label: 'Toggle Live mode (auto-refresh every 30s)' }, { keys: ['t'], label: 'Take the cinematic tour' }] },
    { group: 'Help', items: [{ keys: ['?'], label: 'Show this overlay' }, { keys: ['Esc'], label: 'Close any overlay (this, Cmd-K, modal, tour)' }] },
  ];
}

let overlay = null;

// closeShortcuts closes the overlay.
function closeShortcuts() {
  if (overlay) overlay.close();
}

// toggleShortcuts opens or closes the overlay.
export function toggleShortcuts() {
  if (overlay) {
    closeShortcuts();
    return;
  }
  overlay = openModal({
    className: 'overlay',
    label: 'Keyboard shortcuts',
    html: '<div class="overlay-card"><div class="overlay-head"><div class="fs-14 fw-600">Keyboard shortcuts</div><div class="note">Esc to close</div></div>' +
      '<div class="overlay-body">' + groups().map((g) => `<div class="mb-12"><div class="eyebrow mb-4">${esc(g.group)}</div><table class="kbd-table">` +
        g.items.map((it) => `<tr><td>${it.keys.map((k) => `<kbd>${esc(k)}</kbd>`).join('+')}</td><td>${esc(it.label)}</td></tr>`).join('') +
        '</table></div>').join('') + '</div></div>',
    onClose: () => { overlay = null; },
  });
}

// isTyping reports whether keystrokes belong to a form field.
function isTyping(el) {
  if (!el) return false;
  const tag = (el.tagName || '').toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
}

let chordPending = false;
let chordTimer = null;

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && overlay) {
    e.preventDefault();
    closeShortcuts();
    return;
  }
  if (isTyping(e.target) || e.metaKey || e.ctrlKey || e.altKey) return;
  if (chordPending) {
    chordPending = false;
    clearTimeout(chordTimer);
    const r = chordRoutes.find((x) => x.chord === e.key);
    if (r) {
      e.preventDefault();
      nav(r.id);
    }
    return;
  }
  if (e.key === '?') {
    e.preventDefault();
    toggleShortcuts();
  } else if (e.key === '/' && !overlay) {
    const f = document.getElementById('fSearch');
    if (f) {
      e.preventDefault();
      f.focus();
    }
  } else if (e.key === 'l' && !overlay) {
    e.preventDefault();
    toggleLive();
  } else if (e.key === 't' && !overlay) {
    e.preventDefault();
    startTour();
  } else if (e.key === 'g') {
    e.preventDefault();
    chordPending = true;
    chordTimer = setTimeout(() => { chordPending = false; }, 1200);
  }
});
