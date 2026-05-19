// Inline help drawer for the stats vocabulary fleetsweeper uses. Trends and
// outliers reference R-squared, MAD, t-statistic, confidence levels. Most
// SREs are not statisticians; clicking "Why am I seeing this?" on any of
// these terms opens a panel that explains exactly what fleetsweeper computed
// and why it concluded what it concluded.
//
// Pure frontend; reads only the data already on screen.

(function () {
  'use strict';

  var TOPICS = {
    'mad': {
      title: 'MAD-based outlier detection',
      body: 'Median absolute deviation. For each numeric scanner field, fleetsweeper computes the median across the fleet, then the median of absolute deviations from that median. A cluster is an outlier when its modified z-score (0.6745 × |x − median| / MAD) exceeds the threshold (default 3.5). MAD is robust against outliers in a way that mean+std-dev is not — a single broken cluster cannot inflate the threshold past usefulness.\n\nGuardrails: the fleet must have at least 8 reporting values, and a fleet-wide MAD of zero is suppressed (otherwise every non-mode value looks anomalous on near-uniform integer data).',
    },
    'mode-mass': {
      title: 'String outlier voting',
      body: 'For string fields (versions, classes, types) fleetsweeper uses mode-mass voting. The most common value (the mode) must hold at least 60% of the population before minority values are flagged as outliers. A three-way tied version distribution does not flag two-thirds of the fleet.',
    },
    'r-squared': {
      title: 'R-squared (trend confidence)',
      body: 'The coefficient of determination for the fitted OLS slope. Closer to 1.0 means the trend line fits the historical data well; closer to 0.0 means the data is noisy and a slope direction is unreliable.\n\nFleetsweeper labels a trend "high" confidence when R² ≥ 0.5 AND the slope t-statistic is significant; "low" confidence otherwise. Trends require at least 5 historical points before reporting a non-stable direction.',
    },
    't-statistic': {
      title: 't-statistic gating',
      body: 'A test on whether the fitted slope is statistically distinguishable from zero. If the t-statistic is small relative to its standard error, the apparent trend is likely noise and fleetsweeper labels it stable regardless of R².',
    },
    'severity': {
      title: 'How severities are calibrated',
      body: 'Fleetsweeper is intentionally conservative.\n\n• Critical: something is actively broken (admission webhook with no healthy endpoints, certificate expiring inside 7 days, NotReady nodes).\n• Warning: gap or skew worth fixing (PSS unenforced, deprecated APIs in use, single-minor version skew, missing NetworkPolicy).\n• Info: noteworthy but expected variation (patch-only version skew, busy-but-healthy utilization).\n\nMaximum CPU/memory percentages are warning, not critical, because natural per-cluster variation should not page an SRE.',
    },
    'fleet-policy': {
      title: 'Why "the fleet is the policy"',
      body: 'Rule engines like OPA and Kyverno require you to author a rule before they can flag anything. They are great at "no privileged containers" but useless at "this cluster looks different from the others."\n\nFleetsweeper inverts the question. It derives the norm from your actual fleet — your real version distribution, your real namespace counts, your real warning-event rates — then flags clusters that deviate. You discover the rule, you do not write it.',
    },
  };

  // openHelp surfaces a centered modal explaining the requested topic.
  function openHelp(topic) {
    var t = TOPICS[topic];
    if (!t) return;
    close();
    var root = document.createElement('div');
    root.className = 'modal-root';
    root.id = 'help-modal';
    var paragraphs = t.body.split('\n\n').map(function (p) {
      return '<p style="margin:0 0 12px;color:#c9d1d9;line-height:1.65">' + escapeHTML(p).replace(/\n/g, '<br>') + '</p>';
    }).join('');
    root.innerHTML =
      '<div class="modal-card">' +
      '  <h3 style="display:flex;align-items:center;gap:8px;">' +
      '    <span style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#58a6ff;background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.3);padding:3px 8px;border-radius:999px;">explainer</span>' +
      '    <span>' + escapeHTML(t.title) + '</span>' +
      '  </h3>' +
      '  <div style="margin-top:14px;font-size:14px;">' + paragraphs + '</div>' +
      '  <div class="modal-actions">' +
      '    <button class="tour-btn tour-btn-primary" data-help-act="close">Got it</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(root);
    root.addEventListener('click', function (e) {
      if (e.target === root) close();
    });
    root.querySelector('[data-help-act="close"]').addEventListener('click', close);
  }

  function close() {
    var root = document.getElementById('help-modal');
    if (root) root.remove();
  }

  function escapeHTML(s) {
    var d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  // Delegated click on any element with data-help-topic="X" opens the explainer.
  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-help-topic]');
    if (!el) return;
    e.preventDefault();
    e.stopPropagation();
    openHelp(el.getAttribute('data-help-topic'));
  });

  // openHelpMenu shows a list of topics. Used by the sidebar "How it works"
  // link so operators new to fleetsweeper can browse the stats vocabulary.
  function openHelpMenu() {
    close();
    var root = document.createElement('div');
    root.className = 'modal-root';
    root.id = 'help-modal';
    var items = Object.keys(TOPICS).map(function (k) {
      return (
        '<button data-help-pick="' + k + '" style="text-align:left;background:transparent;border:1px solid var(--bd);color:var(--tx);padding:12px 14px;border-radius:8px;cursor:pointer;font-family:inherit;display:block;width:100%;margin-bottom:8px;transition:all 120ms ease">' +
        '  <div style="font-weight:600;font-size:14px;margin-bottom:2px">' + escapeHTML(TOPICS[k].title) + '</div>' +
        '  <div style="font-size:12px;color:var(--t2)">' + escapeHTML(TOPICS[k].body.split('\n')[0].slice(0, 96)) + '...</div>' +
        '</button>'
      );
    }).join('');
    root.innerHTML =
      '<div class="modal-card">' +
      '  <h3>How fleetsweeper works</h3>' +
      '  <p class="modal-sub">The math behind outliers, trends, and findings. Pick a topic.</p>' +
      '  <div style="margin-top:14px;">' + items + '</div>' +
      '  <div class="modal-actions">' +
      '    <button class="tour-btn tour-btn-ghost" data-help-act="close">Close</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(root);
    root.addEventListener('click', function (e) {
      if (e.target === root) close();
    });
    root.querySelector('[data-help-act="close"]').addEventListener('click', close);
    root.querySelectorAll('[data-help-pick]').forEach(function (b) {
      b.addEventListener('click', function () { openHelp(b.getAttribute('data-help-pick')); });
      b.addEventListener('mouseenter', function () { b.style.borderColor = 'rgba(88,166,255,0.4)'; });
      b.addEventListener('mouseleave', function () { b.style.borderColor = 'var(--bd)'; });
    });
  }

  window.Help = { open: openHelp, openMenu: openHelpMenu, close: close };
})();
