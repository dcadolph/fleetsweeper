// The drawer: a panel that slides in from the right for a short form or a
// confirmation, in place of the browser's alert, prompt, and confirm. One is
// open at a time. Escape, the overlay, and Cancel close it, focus stays
// inside it while open, and it returns focus where it came from.

import { esc } from '../dom.js';

let current = null;

// FOCUSABLE selects the elements Tab moves between.
const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

// closeDrawer closes the open drawer, if any.
export function closeDrawer() {
  if (!current) return;
  const { root, restore, onKey } = current;
  current = null;
  document.removeEventListener('keydown', onKey, true);
  root.remove();
  if (restore && restore.focus) restore.focus();
}

// openDrawer opens a drawer with a title, body markup, and buttons. Each
// action is {label, tone, run}: run gets the drawer element and may be
// async; the drawer closes when it returns anything but false. Buttons are
// disabled while a run is in flight. It returns the drawer element.
export function openDrawer({ title, body, actions }) {
  closeDrawer();
  const root = document.createElement('div');
  root.className = 'drawer-root';
  const acts = (actions || []).concat([{ label: 'Cancel', tone: 'ghost', run: () => true }]);
  root.innerHTML = '<div class="drawer-overlay"></div>' +
    `<aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle"><h3 id="drawerTitle">${esc(title)}</h3>` +
    `<div class="drawer-body">${body || ''}</div><div class="drawer-actions">` +
    acts.map((a, i) => `<button class="btn ${a.tone === 'primary' ? 'btn-ac' : a.tone === 'danger' ? 'btn-crit' : ''}" data-i="${i}">${esc(a.label)}</button>`).join('') +
    '</div></aside>';
  const panel = root.querySelector('.drawer');
  root.querySelector('.drawer-overlay').addEventListener('click', closeDrawer);
  panel.querySelector('.drawer-actions').addEventListener('click', async (ev) => {
    const btn = ev.target.closest('button[data-i]');
    if (!btn) return;
    const buttons = panel.querySelectorAll('.drawer-actions button');
    buttons.forEach((b) => { b.disabled = true; });
    let result;
    try {
      result = await acts[Number(btn.dataset.i)].run(panel);
    } finally {
      buttons.forEach((b) => { b.disabled = false; });
    }
    if (result !== false && current && current.root === root) closeDrawer();
  });
  const onKey = (ev) => {
    if (ev.key === 'Escape') {
      ev.preventDefault();
      ev.stopPropagation();
      closeDrawer();
      return;
    }
    if (ev.key !== 'Tab') return;
    const items = [...panel.querySelectorAll(FOCUSABLE)].filter((x) => !x.disabled);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  };
  document.addEventListener('keydown', onKey, true);
  current = { root, restore: document.activeElement, onKey };
  document.body.appendChild(root);
  const focus = panel.querySelector('input, select, textarea') || panel.querySelector('.drawer-actions button');
  if (focus) focus.focus();
  return panel;
}
