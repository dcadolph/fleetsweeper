// Toasts: short notices in the corner for the outcome of an action or a
// live event, announced to screen readers, dismissed by a click or after a
// few seconds. An error toast stays until dismissed and may carry one action.

import { esc } from '../dom.js';

// LINGER_MS is how long a non-error toast stays.
const LINGER_MS = 5000;

// stack returns the toast container, creating it on first use. While a modal
// dialog is open everything outside it is inert, so toasts then live inside
// the topmost open dialog, where their buttons still work.
function stack() {
  const dialogs = document.querySelectorAll('dialog.modal[open]');
  const host = dialogs.length ? dialogs[dialogs.length - 1] : document.body;
  let el = host.querySelector(':scope > .toasts');
  if (!el) {
    el = document.createElement('div');
    el.className = 'toasts';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    host.appendChild(el);
  }
  return el;
}

// adoptToasts moves the toasts living in a closing dialog to the page, so a
// notice raised just before the dialog closed stays readable.
export function adoptToasts(dialog) {
  const moving = [...dialog.querySelectorAll(':scope > .toasts > .toast')];
  if (!moving.length) return;
  const target = stack();
  moving.forEach((t) => target.appendChild(t));
}

// toast shows message in tone (ok, warn, crit, info). action, when given, is
// {label, run} and adds a button that runs it and dismisses the toast. It
// returns a function that dismisses the toast.
export function toast(message, tone, action) {
  const t = tone || 'info';
  const el = document.createElement('div');
  el.className = 'toast toast-' + t;
  el.innerHTML = `<span class="toast-msg">${esc(message)}</span>` +
    (action ? `<button class="btn btn-sm toast-act">${esc(action.label)}</button>` : '') +
    '<button class="toast-x" aria-label="Dismiss">&times;</button>';
  let timer = null;
  const dismiss = () => {
    clearTimeout(timer);
    el.remove();
  };
  el.querySelector('.toast-x').addEventListener('click', dismiss);
  if (action) {
    el.querySelector('.toast-act').addEventListener('click', () => {
      dismiss();
      action.run();
    });
  }
  stack().appendChild(el);
  if (t !== 'crit') timer = setTimeout(dismiss, LINGER_MS);
  return dismiss;
}
