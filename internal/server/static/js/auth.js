// Write actions and the API token. A token pasted into the token drawer is
// kept in sessionStorage for this tab and sent as a bearer token; an OIDC
// session cookie, when the server set one, rides along on its own. Every
// write goes through send(), which surfaces the server's error in a toast.

import { apiSend, errorText } from './api.js';
import { openDrawer } from './components/drawer.js';
import { toast } from './components/toast.js';

// TOKEN_KEY is the sessionStorage key api.js reads the token from.
const TOKEN_KEY = 'fleetsweeper-token';

const listeners = [];

// hasToken reports whether this tab holds a token.
export function hasToken() {
  try {
    return !!sessionStorage.getItem(TOKEN_KEY);
  } catch (_) {
    return false;
  }
}

// setToken saves token for this tab, or clears it when empty, and tells the
// listeners.
function setToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch (_) {
    toast('This browser will not keep a token for the tab.', 'crit');
    return;
  }
  listeners.forEach((fn) => fn(!!token));
}

// onTokenChange registers fn(has) to run when the token is set or cleared.
export function onTokenChange(fn) {
  listeners.push(fn);
}

// openTokenDrawer asks for an API token and saves it for this tab.
export function openTokenDrawer() {
  const set = hasToken();
  openDrawer({
    title: 'API token',
    body: '<p class="note mb-8">Acknowledging findings and starting scans need a token when the server runs with ' +
      '<code>--auth-token</code> or API keys. It stays in this tab only and is never written to disk. ' +
      'A single sign-on session needs no token.</p>' +
      `<label class="field"><span>Token</span><input type="password" id="tokenInput" autocomplete="off" spellcheck="false" placeholder="${set ? 'A token is set. Paste a new one to replace it.' : 'Paste a token'}"></label>`,
    actions: [
      {
        label: 'Save',
        tone: 'primary',
        run: (panel) => {
          const v = panel.querySelector('#tokenInput').value.trim();
          if (!v) {
            toast('Paste a token first.', 'warn');
            return false;
          }
          setToken(v);
          toast('Token saved for this tab.', 'ok');
          return true;
        },
      },
    ].concat(set ? [{
      label: 'Forget token',
      tone: 'danger',
      run: () => {
        setToken('');
        toast('Token cleared.', 'info');
        return true;
      },
    }] : []),
  });
}

// send performs a write and returns the Response when it succeeded, or null
// after showing why it failed. what names the action for the toast, e.g.
// "Acknowledge". A 401 or 403 offers the token drawer.
export async function send(method, path, body, what) {
  let r;
  try {
    r = await apiSend(method, path, body);
  } catch (e) {
    toast(`${what} failed: ${e.message}`, 'crit');
    return null;
  }
  if (r.ok) return r;
  const msg = await errorText(r);
  const auth = r.status === 401 || r.status === 403;
  toast(`${what} failed: ${msg} (${r.status}).`, 'crit',
    auth ? { label: hasToken() ? 'Change token' : 'Set token', run: openTokenDrawer } : null);
  return null;
}
