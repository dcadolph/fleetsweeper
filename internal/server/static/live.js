// Live mode. Re-runs the current page's render function on an interval so
// the dashboard refreshes without a manual reload. The pulsing green dot in
// the top bar gives operators visual confirmation that data is fresh.

(function () {
  'use strict';

  var INTERVAL_MS = 30000;
  var state = { on: false, timer: null, lastTick: 0 };

  function start() {
    if (state.on) return;
    state.on = true;
    state.lastTick = Date.now();
    schedule();
    paintToggle();
  }

  function stop() {
    state.on = false;
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    paintToggle();
  }

  function toggle() {
    if (state.on) stop(); else start();
  }

  function schedule() {
    if (!state.on) return;
    state.timer = setTimeout(function () {
      tick();
      schedule();
    }, INTERVAL_MS);
  }

  function tick() {
    state.lastTick = Date.now();
    paintToggle();
    if (typeof window.render === 'function') {
      // The SPA's render() reads window.P and rebuilds the current page.
      try { window.render(); } catch (_) {}
    }
  }

  function paintToggle() {
    var btn = document.getElementById('live-toggle');
    if (!btn) return;
    btn.className = 'live-toggle' + (state.on ? ' on' : '');
    var ago = state.on ? humanAgo(Date.now() - state.lastTick) : 'paused';
    btn.innerHTML = '<span class="live-dot"></span><span>Live · ' + ago + '</span>';
  }

  function humanAgo(ms) {
    if (ms < 5000) return 'just now';
    var s = Math.round(ms / 1000);
    if (s < 60) return s + 's ago';
    var m = Math.round(s / 60);
    return m + 'm ago';
  }

  // Repaint the "X seconds ago" label every few seconds even when no fetch
  // is happening, so the indicator doesn't look frozen.
  setInterval(function () { if (state.on) paintToggle(); }, 5000);

  window.LiveMode = {
    start: start,
    stop: stop,
    toggle: toggle,
    isOn: function () { return state.on; },
    paint: paintToggle,
  };
})();
