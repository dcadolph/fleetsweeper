// Live updates. With live on, the page listens to the server's event stream:
// when a scan completes it refreshes the current view in place and says so in
// a toast, a failed scan raises an error toast, and an inbound alert refreshes
// the alerts page. Live starts on, and the choice is remembered per viewer.

import { refresh, P } from './router.js';
import { toast } from './components/toast.js';

// STORE_KEY is the localStorage key of the viewer's choice.
const STORE_KEY = 'fleetsweeper-live';

const state = { on: true, source: null, connected: false };

// payloadOf returns the payload of a server event, or an empty object.
function payloadOf(ev) {
  try {
    return JSON.parse(ev.data).payload || {};
  } catch (_) {
    return {};
  }
}

// connect opens the event stream. EventSource reconnects on its own after a
// dropped connection.
function connect() {
  if (state.source || typeof EventSource === 'undefined') return;
  const es = new EventSource('/api/events');
  state.source = es;
  es.onopen = () => {
    state.connected = true;
    paintLive();
  };
  es.onerror = () => {
    state.connected = false;
    paintLive();
  };
  es.addEventListener('scan.complete', (ev) => {
    const p = payloadOf(ev);
    toast(`Scan complete${typeof p.score === 'number' ? `: fleet score ${p.score} (${p.grade})` : ''}.`, 'ok');
    refresh();
  });
  es.addEventListener('scan.failed', (ev) => {
    toast('Scan failed: ' + (payloadOf(ev).error || 'no reason given') + '.', 'crit');
  });
  es.addEventListener('alert.received', () => {
    if (P.page === 'alerts') refresh();
  });
}

// disconnect closes the event stream.
function disconnect() {
  if (state.source) state.source.close();
  state.source = null;
  state.connected = false;
}

// isLive reports whether live updates are on.
export function isLive() {
  return state.on;
}

// startLive applies the viewer's saved choice at boot.
export function startLive() {
  try {
    state.on = localStorage.getItem(STORE_KEY) !== 'off';
  } catch (_) {
    state.on = true;
  }
  if (state.on) connect();
  paintLive();
}

// toggleLive turns live updates on or off and remembers the choice.
export function toggleLive() {
  state.on = !state.on;
  if (state.on) connect();
  else disconnect();
  try {
    localStorage.setItem(STORE_KEY, state.on ? 'on' : 'off');
  } catch (_) { /* the choice lasts for this page only */ }
  paintLive();
}

// paintLive updates the live toggle's label.
export function paintLive() {
  const btn = document.getElementById('live-toggle');
  if (!btn) return;
  btn.className = 'live-toggle' + (state.on && state.connected ? ' on' : '');
  btn.setAttribute('aria-pressed', String(state.on));
  btn.lastElementChild.textContent = !state.on ? 'Live · paused' : state.connected ? 'Live' : 'Live · connecting';
}
