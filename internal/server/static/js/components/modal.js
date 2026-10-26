// The modal: every overlay the dashboard opens over the page is a native
// <dialog> shown with showModal(), so the page behind is inert, focus stays
// inside, Escape closes it, and focus returns where it was.

import { adoptToasts } from './toast.js';

// openModal shows html in a modal dialog carrying className and named by
// label. A click on the dialog's own backdrop area closes it. onClose runs
// after it closes and is removed. It returns the dialog.
export function openModal({ className, label, id, html, onClose }) {
  const restore = document.activeElement;
  const dlg = document.createElement('dialog');
  dlg.className = 'modal ' + (className || '');
  if (id) dlg.id = id;
  if (label) dlg.setAttribute('aria-label', label);
  dlg.innerHTML = html;
  document.body.appendChild(dlg);
  dlg.addEventListener('click', (e) => {
    if (e.target === dlg) dlg.close();
  });
  dlg.addEventListener('close', () => {
    adoptToasts(dlg);
    dlg.remove();
    if (restore && restore.isConnected && restore.focus) restore.focus();
    if (onClose) onClose();
  });
  dlg.showModal();
  return dlg;
}
