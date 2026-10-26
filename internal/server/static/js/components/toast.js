// Toasts: short notices in the corner for the outcome of an action or a
// live event, announced to screen readers, dismissed by a click or after a
// few seconds. An error toast stays until dismissed and may carry one action.

import { esc } from '../dom.js';

// LINGER_MS is how long a non-error toast stays.
const LINGER_MS = 5000;

// stack returns the toast container, creating it on first use.
function stack() {
  let el = document.getElementById('toasts');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toasts';
    el.className = 'toasts';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  return el;
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
