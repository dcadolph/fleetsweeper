// Live mode. Re-renders the current page every 30 seconds so the dashboard
// refreshes without a reload. The pulsing dot in the top bar shows it is on.

import { render } from './router.js';

const INTERVAL_MS = 30000;
const state = { on: false, timer: null, lastTick: 0 };

// schedule arms the next refresh.
function schedule() {
  if (!state.on) return;
  state.timer = setTimeout(() => {
    state.lastTick = Date.now();
    paintLive();
    render();
    schedule();
  }, INTERVAL_MS);
}

// toggleLive turns live mode on or off.
export function toggleLive() {
  if (state.on) {
    state.on = false;
    clearTimeout(state.timer);
    state.timer = null;
  } else {
    state.on = true;
    state.lastTick = Date.now();
    schedule();
  }
  paintLive();
}

// paintLive updates the live toggle's label.
export function paintLive() {
  const btn = document.getElementById('live-toggle');
  if (!btn) return;
  btn.className = 'live-toggle' + (state.on ? ' on' : '');
  btn.setAttribute('aria-pressed', String(state.on));
  btn.lastElementChild.textContent = 'Live · ' + (state.on ? ago(Date.now() - state.lastTick) : 'paused');
}

// ago formats a duration in milliseconds as "just now", "Ns ago", or "Nm ago".
function ago(ms) {
  if (ms < 5000) return 'just now';
  const s = Math.round(ms / 1000);
  return s < 60 ? s + 's ago' : Math.round(s / 60) + 'm ago';
}

setInterval(() => { if (state.on) paintLive(); }, 5000);
