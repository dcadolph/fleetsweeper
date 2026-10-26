// The drawer: a panel that slides in from the right for a short form or a
// confirmation, in place of the browser's alert, prompt, and confirm. One is
// open at a time. It is a native modal dialog: Escape, the overlay, and Cancel
// close it, focus stays inside it while open, and it returns focus where it
// came from.

import { esc } from '../dom.js';
import { openModal } from './modal.js';

let current = null;

// closeDrawer closes the open drawer, if any.
export function closeDrawer() {
  if (current) current.close();
}

// openDrawer opens a drawer with a title, body markup, and buttons. Each
// action is {label, tone, run}: run gets the drawer element and may be
// async; the drawer closes when it returns anything but false. Buttons are
// disabled while a run is in flight. It returns the drawer element.
export function openDrawer({ title, body, actions }) {
  closeDrawer();
  const acts = (actions || []).concat([{ label: 'Cancel', tone: 'ghost', run: () => true }]);
  const dlg = openModal({
    className: 'drawer-root',
    html: '<div class="drawer-overlay"></div>' +
      `<aside class="drawer" aria-labelledby="drawerTitle"><h3 id="drawerTitle">${esc(title)}</h3>` +
      `<div class="drawer-body">${body || ''}</div><div class="drawer-actions">` +
      acts.map((a, i) => `<button class="btn ${a.tone === 'primary' ? 'btn-ac' : a.tone === 'danger' ? 'btn-crit' : ''}" data-i="${i}">${esc(a.label)}</button>`).join('') +
      '</div></aside>',
    onClose: () => {
      if (current === dlg) current = null;
    },
  });
  dlg.setAttribute('aria-labelledby', 'drawerTitle');
  current = dlg;
  const panel = dlg.querySelector('.drawer');
  dlg.querySelector('.drawer-overlay').addEventListener('click', () => dlg.close());
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
    if (result !== false && dlg.open) dlg.close();
  });
  const focus = panel.querySelector('input, select, textarea') || panel.querySelector('.drawer-actions button');
  if (focus) focus.focus();
  return panel;
}
