// Keyboard shortcuts overlay. Press "?" anywhere outside an input to bring up
// the cheat sheet. Esc closes. Lives in its own file so the main bundle stays
// focused on dashboard rendering.

(function () {
  'use strict';

  var SHORTCUTS = [
    { group: 'Navigation', items: [
      { keys: ['Cmd', 'K'], label: 'Open command palette (clusters, scanners, pages)' },
      { keys: ['g', 'd'], label: 'Go to Dashboard' },
      { keys: ['g', 'f'], label: 'Go to Findings' },
      { keys: ['g', 'g'], label: 'Go to Globe' },
      { keys: ['g', 'c'], label: 'Go to Capacity' },
      { keys: ['g', 't'], label: 'Go to Trends' },
      { keys: ['g', 'o'], label: 'Go to Outliers' },
      { keys: ['g', 'h'], label: 'Go to Scan history' },
    ]},
    { group: 'Findings page', items: [
      { keys: ['/'], label: 'Focus the filter input' },
    ]},
    { group: 'Live & tour', items: [
      { keys: ['l'], label: 'Toggle Live mode (auto-refresh every 30s)' },
      { keys: ['t'], label: 'Take the cinematic tour' },
    ]},
    { group: 'Help', items: [
      { keys: ['?'], label: 'Show this overlay' },
      { keys: ['Esc'], label: 'Close any overlay (this, Cmd-K, modal, tour)' },
    ]},
  ];

  var overlay = null;

  function open() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.id = 'shortcuts-overlay';
    overlay.style.cssText =
      'position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:10000;' +
      'display:flex;align-items:flex-start;justify-content:center;padding-top:60px;';
    overlay.innerHTML =
      '<div style="background:var(--c1);border:1px solid var(--bd);border-radius:10px;' +
      'width:560px;max-width:92vw;max-height:80vh;display:flex;flex-direction:column;' +
      'overflow:hidden;box-shadow:0 12px 40px rgba(0,0,0,.5)">' +
      '  <div style="padding:14px 18px;border-bottom:1px solid var(--bd);display:flex;' +
      'align-items:center;justify-content:space-between">' +
      '    <div style="font-size:14px;font-weight:600;color:var(--tx)">Keyboard shortcuts</div>' +
      '    <div style="font-size:11px;color:var(--t3)">Esc to close</div>' +
      '  </div>' +
      '  <div id="shortcuts-body" style="padding:14px 18px;overflow-y:auto"></div>' +
      '</div>';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    var body = overlay.querySelector('#shortcuts-body');
    body.innerHTML = SHORTCUTS.map(renderGroup).join('');
  }

  function close() {
    if (!overlay) return;
    overlay.remove();
    overlay = null;
  }

  function toggle() { if (overlay) close(); else open(); }

  function renderGroup(g) {
    return (
      '<div style="margin-bottom:14px">' +
      '  <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;' +
      'color:var(--t3);margin-bottom:6px;font-weight:600">' + esc(g.group) + '</div>' +
      '  <table style="width:100%;font-size:13px">' +
      g.items.map(renderItem).join('') +
      '  </table>' +
      '</div>'
    );
  }

  function renderItem(it) {
    var keys = it.keys.map(function (k) {
      return '<kbd style="display:inline-block;padding:2px 7px;margin:0 2px;' +
        'background:var(--c2);border:1px solid var(--bd);border-bottom-width:2px;' +
        'border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--tx);' +
        'min-width:18px;text-align:center">' + esc(k) + '</kbd>';
    }).join('<span style="color:var(--t3);margin:0 2px;font-size:10px">+</span>');
    return (
      '<tr>' +
      '  <td style="padding:4px 10px 4px 0;color:var(--t2);width:140px;vertical-align:top">' + keys + '</td>' +
      '  <td style="padding:4px 0;color:var(--tx);vertical-align:top">' + esc(it.label) + '</td>' +
      '</tr>'
    );
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  // Navigation chord state: "g" followed by a target key jumps to a page.
  // Times out after 1.2s so a stale "g" press does not hijack later keystrokes.
  var chordPending = false;
  var chordTimer = null;
  var CHORD_TARGETS = {
    d: 'dash', f: 'findings', g: 'globe', c: 'capacity',
    t: 'trends', o: 'outliers', h: 'scans',
  };

  function startChord() {
    chordPending = true;
    if (chordTimer) clearTimeout(chordTimer);
    chordTimer = setTimeout(function () { chordPending = false; }, 1200);
  }

  function resolveChord(key) {
    chordPending = false;
    if (chordTimer) { clearTimeout(chordTimer); chordTimer = null; }
    var target = CHORD_TARGETS[key];
    if (target && typeof window.nav === 'function') {
      window.nav(target);
      return true;
    }
    return false;
  }

  function isTypingTarget(el) {
    if (!el) return false;
    var tag = (el.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return true;
    if (el.isContentEditable) return true;
    return false;
  }

  document.addEventListener('keydown', function (e) {
    // Esc always closes overlay if open, even from inside inputs.
    if (e.key === 'Escape' && overlay) {
      e.preventDefault();
      close();
      return;
    }
    if (isTypingTarget(e.target)) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    if (chordPending) {
      var consumed = resolveChord(e.key);
      if (consumed) e.preventDefault();
      return;
    }

    if (e.key === '?') {
      e.preventDefault();
      toggle();
      return;
    }
    if (e.key === '/' && !overlay) {
      // Focus the findings filter input when present.
      var f = document.getElementById('fSearch');
      if (f) { f.focus(); e.preventDefault(); }
      return;
    }
    if (e.key === 'l' && !overlay) {
      if (window.LiveMode) { window.LiveMode.toggle(); e.preventDefault(); }
      return;
    }
    if (e.key === 't' && !overlay) {
      if (window.Tour) { window.Tour.start(); e.preventDefault(); }
      return;
    }
    if (e.key === 'g') {
      startChord();
      e.preventDefault();
      return;
    }
  });

  window.Shortcuts = { open: open, close: close, toggle: toggle };
})();
