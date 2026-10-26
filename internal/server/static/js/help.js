// The help explainers: what fleetsweeper computes and why, opened from the
// sidebar or from any element with data-help-topic.

import { esc } from './dom.js';

const TOPICS = {
  mad: {
    title: 'MAD-based outlier detection',
    body: 'Median absolute deviation. For each numeric scanner field, fleetsweeper computes the median across the fleet, then the median of absolute deviations from that median. A cluster is an outlier when its modified z-score (0.6745 × |x − median| / MAD) exceeds the threshold (default 3.5). MAD is robust against outliers in a way that mean+std-dev is not. A single broken cluster cannot inflate the threshold past usefulness.\n\nGuardrails: the fleet must have at least 8 reporting values, and a fleet-wide MAD of zero is suppressed (otherwise every non-mode value looks anomalous on near-uniform integer data).',
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
  severity: {
    title: 'How severities are calibrated',
    body: 'Fleetsweeper is intentionally conservative.\n\n• Critical: something is actively broken (admission webhook with no healthy endpoints, certificate expiring inside 7 days, NotReady nodes).\n• Warning: gap or skew worth fixing (PSS unenforced, deprecated APIs in use, single-minor version skew, missing NetworkPolicy).\n• Info: noteworthy but expected variation (patch-only version skew, busy-but-healthy utilization).\n\nMaximum CPU/memory percentages are warning, not critical, because natural per-cluster variation should not page an SRE.',
  },
  'fleet-policy': {
    title: 'Why "the fleet is the policy"',
    body: 'Rule engines like OPA and Kyverno require you to author a rule before they can flag anything. They are great at "no privileged containers" but useless at "this cluster looks different from the others."\n\nFleetsweeper inverts the question. It derives the norm from your actual fleet (your real version distribution, your real namespace counts, your real warning-event rates) then flags clusters that deviate. You discover the rule, you do not write it.',
  },
};

// closeHelp removes the open help modal.
function closeHelp() {
  const root = document.getElementById('help-modal');
  if (root) root.remove();
}

// mount shows a help modal with the given card markup.
function mount(card) {
  closeHelp();
  const root = document.createElement('div');
  root.className = 'modal-root';
  root.id = 'help-modal';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.innerHTML = `<div class="modal-card">${card}</div>`;
  document.body.appendChild(root);
  root.addEventListener('click', (e) => {
    if (e.target === root || e.target.closest('[data-help-act="close"]')) closeHelp();
    const pick = e.target.closest('[data-help-pick]');
    if (pick) openHelp(pick.dataset.helpPick);
  });
  const first = root.querySelector('button');
  if (first) first.focus();
}

// openHelp explains one topic.
export function openHelp(topic) {
  const t = TOPICS[topic];
  if (!t) return;
  mount(`<h3 class="flex items-center gap-8"><span class="help-pill">explainer</span><span>${esc(t.title)}</span></h3>` +
    '<div class="help-body">' + t.body.split('\n\n').map((p) => `<p>${esc(p).replace(/\n/g, '<br>')}</p>`).join('') + '</div>' +
    '<div class="modal-actions"><button class="tour-btn tour-btn-primary" data-help-act="close">Got it</button></div>');
}

// openHelpMenu lists every topic.
export function openHelpMenu() {
  mount('<h3>How fleetsweeper works</h3><p class="modal-sub">The math behind outliers, trends, and findings. Pick a topic.</p><div class="mt-12">' +
    Object.keys(TOPICS).map((k) => `<button class="help-pick" data-help-pick="${k}"><span class="fs-14 fw-600">${esc(TOPICS[k].title)}</span>` +
      `<span class="fs-12 c-t2">${esc(TOPICS[k].body.split('\n')[0].slice(0, 96))}...</span></button>`).join('') +
    '</div><div class="modal-actions"><button class="tour-btn tour-btn-ghost" data-help-act="close">Close</button></div>');
}

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-help-topic]');
  if (!el) return;
  e.preventDefault();
  openHelp(el.dataset.helpTopic);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeHelp();
});
