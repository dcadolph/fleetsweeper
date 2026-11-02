// Live updates. With live on, the page listens to the server's event stream:
// when a scan completes it refreshes the current view in place and says so in
// a toast, a failed scan raises an error toast, and an inbound alert refreshes
// the alerts page. Live starts on, and the choice is remembered per viewer.

import { refresh, P } from './router.js';
import { toast } from './components/toast.js';
import { authHeaders } from './api.js';

// STORE_KEY is the localStorage key of the viewer's choice.
const STORE_KEY = 'fleetsweeper-live';

// state.source is the AbortController of the open stream, or null.
const state = { on: true, source: null, connected: false };

// payloadOf returns the payload of a server event, or an empty object.
function payloadOf(data) {
  try {
    return JSON.parse(data).payload || {};
  } catch (_) {
    return {};
  }
}

// RETRY_MS is how long the stream waits before it reconnects after a drop.
const RETRY_MS = 3000;

// handleEvent acts on one server event.
function handleEvent(type, data) {
  if (type === 'scan.complete') {
    const p = payloadOf(data);
    toast(`Scan complete${typeof p.score === 'number' ? (p.grade ? `: fleet score ${p.score} (${p.grade})` : ': not graded, too little of the fleet was observed') : ''}.`, 'ok');
    refresh();
  } else if (type === 'scan.failed') {
    toast('Scan failed: ' + (payloadOf(data).error || 'no reason given') + '.', 'crit');
  } else if (type === 'alert.received') {
    if (P.page === 'alerts') refresh();
  }
}

// readStream parses the server-sent events in body and hands each to
// handleEvent until the stream ends.
async function readStream(body) {
  const reader = body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += value;
    let at;
    while ((at = buf.indexOf('\n\n')) >= 0) {
      const block = buf.slice(0, at);
      buf = buf.slice(at + 2);
      let type = 'message';
      const data = [];
      block.split('\n').forEach((line) => {
        if (line.startsWith('event:')) type = line.slice(6).trim();
        else if (line.startsWith('data:')) data.push(line.slice(5).trimStart());
      });
      if (data.length) handleEvent(type, data.join('\n'));
    }
  }
}

// connect opens the event stream with the tab's credential. The stream is read
// with fetch rather than EventSource so it can carry the bearer token. A drop
// reconnects after RETRY_MS. A 401 stops until the token changes.
async function connect() {
  if (state.source) return;
  const ctl = new AbortController();
  state.source = ctl;
  while (state.source === ctl) {
    let stop = false;
    try {
      const r = await fetch('/api/events', { headers: { Accept: 'text/event-stream', ...authHeaders() }, signal: ctl.signal });
      if (r.ok && r.body) {
        state.connected = true;
        paintLive();
        await readStream(r.body);
      } else if (r.status === 401 || r.status === 403) {
        stop = true;
      }
    } catch (_) { /* dropped or aborted */ }
    state.connected = false;
    paintLive();
    if (stop || state.source !== ctl) break;
    await new Promise((done) => setTimeout(done, RETRY_MS));
  }
  if (state.source === ctl) state.source = null;
}

// disconnect closes the event stream.
function disconnect() {
  if (state.source) state.source.abort();
  state.source = null;
  state.connected = false;
}

// reconnectLive reopens the stream with the current credential when live
// updates are on.
export function reconnectLive() {
  disconnect();
  if (state.on) connect();
  paintLive();
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
