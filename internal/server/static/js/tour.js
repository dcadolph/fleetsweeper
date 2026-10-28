// The cinematic guided tour. Walks a viewer through the main pages with a
// spotlight overlay and an explainer card. Steps auto-advance after their
// dwell time, with Next, Back, Pause, and Exit always available.

import { nav, P } from './router.js';
import { esc } from './dom.js';

var DEFAULT_DWELL = 7000;
var WAIT_TIMEOUT = 5000;
var WAIT_INTERVAL = 80;

var state = {
  active: false,
  paused: false,
  index: 0,
  steps: [],
  timer: null,
  root: null,
  overlay: null,
  spotlight: null,
  card: null,
  progressBar: null,
  el: null,
  startedAt: 0,
  pausedFraction: 0,
};

// STEPS describes the default tour. Each step navigates to a page,
// optionally invokes an action (such as opening a cluster), waits for the
// anchor selector to appear, then renders the explainer card next to it.
// STEPS: 4-5 second dwells, ~15-20 word bodies, one delight per step. Pace
// is intentionally fast: an operator should leave the tour wanting to click,
// not waiting for the next slide.
var STEPS = [
  {
    hero: true,
    title: 'The fleet is the policy.',
    body: 'No rules to write. Every cluster is measured against its peers. Here is what drift looks like.',
    dwell: 5000,
  },
  {
    page: 'dash',
    selector: '[data-tour="fleet-score"]',
    title: 'One number for the status TV.',
    body: 'Fleet Score rolls up findings, cluster health, and version skew. Lower is worse.',
    position: 'bottom',
    dwell: 4500,
  },
  {
    page: 'globe',
    selector: '#globe-wrap',
    title: 'Where the trouble lives.',
    body: 'Critical clusters pulse red. The camera focuses on them so the eye lands on trouble first.',
    position: 'left',
    dwell: 5000,
  },
  {
    page: 'dash',
    selector: '[data-tour="cluster-table"]',
    title: 'Sorted by trouble, not by name.',
    body: 'Critical first, then the points each cluster costs and how far it sits from the norm.',
    position: 'top',
    dwell: 4500,
  },
  {
    page: 'detail',
    cluster: 'prod-us-east-1',
    selector: '[data-tour="findings-list"], .fi',
    title: 'Findings name the offender.',
    body: 'Exact nodes, pods, bindings, images. Parameterized kubectl attached. Paste, run, done.',
    position: 'right',
    dwell: 5500,
  },
  {
    page: 'outliers',
    selector: '.strip',
    title: 'Statistical, not opinionated.',
    body: 'MAD outlier detection on numbers, mode voting on strings. Your fleet is the baseline.',
    position: 'left',
    dwell: 5000,
  },
  {
    page: 'trends',
    selector: '.multiples',
    title: 'Trends with a confidence gate.',
    body: 'OLS regression with R-squared and t-stat gating. Noise will not flip an arrow.',
    position: 'left',
    dwell: 4500,
  },
  {
    page: 'capacity',
    selector: '#ct .g3 .cd',
    title: 'Capacity, correlated with pressure.',
    body: 'Headroom, OOM events, scheduling failures, all in one row, with a recommendation.',
    position: 'left',
    dwell: 4500,
  },
  {
    page: 'manage',
    selector: '.manage-grid, #ct [data-empty]',
    title: 'Now point it at your real fleet.',
    body: 'Restart with --kubeconfig. Every reachable context shows up here. Click Scan.',
    position: 'left',
    dwell: 5000,
  },
  {
    hero: true,
    title: 'That is Fleetsweeper.',
    body: 'Press ? for shortcuts. Cmd-K to jump anywhere. Relaunch this tour from the top bar.',
    dwell: 6000,
    isFinal: true,
  },
];

export function startTour(custom) {
  state.steps = custom && custom.length ? custom : STEPS;
  state.index = 0;
  state.paused = false;
  state.active = true;
  if (!state.root) {
    buildRoot();
  }
  state.root.classList.remove('hidden');
  document.body.classList.add('modal-open');
  show(0);
}

function stop() {
  state.active = false;
  if (state.timer) {
    clearTimeout(state.timer);
    state.timer = null;
  }
  if (state.root) {
    state.root.classList.add('hidden');
  }
  document.body.classList.remove('modal-open');
}

function next() {
  if (state.index >= state.steps.length - 1) {
    stop();
    return;
  }
  show(state.index + 1);
}

function prev() {
  if (state.index <= 0) {
    return;
  }
  show(state.index - 1);
}

function toggle() {
  if (!state.active) {
    return;
  }
  state.paused = !state.paused;
  if (state.paused) {
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    if (state.progressBar) {
      var bar = state.progressBar;
      var computed = window.getComputedStyle(bar).width;
      bar.classList.add('paused');
      bar.style.width = computed;
    }
    updateControls();
  } else {
    armTimer(currentStep());
    updateControls();
  }
}

function currentStep() {
  return state.steps[state.index];
}

function show(i) {
  state.index = i;
  var step = state.steps[i];
  if (!step) {
    stop();
    return;
  }
  state.paused = false;
  if (state.timer) {
    clearTimeout(state.timer);
    state.timer = null;
  }
  if (step.page && step.page !== currentPage()) {
    try {
      if (step.page === 'detail' && step.cluster) {
        nav('detail', { cluster: step.cluster });
      } else {
        nav(step.page);
      }
    } catch (e) {
      // The route may not exist (e.g. manage on older builds). Ignore.
    }
  }
  waitForSelector(step.hero ? null : step.selector, function (el) {
    renderStep(step, el);
    armTimer(step);
  });
}

function armTimer(step) {
  if (state.paused) {
    return;
  }
  var dwell = step.dwell || DEFAULT_DWELL;
  if (state.progressBar) {
    state.progressBar.classList.remove('paused');
    state.progressBar.style.transition = 'none';
    state.progressBar.style.width = '0';
    // Force reflow so the next width animation actually fires.
    void state.progressBar.offsetWidth;
    state.progressBar.style.transition = 'width ' + dwell + 'ms linear';
    state.progressBar.style.width = '100%';
  }
  state.timer = setTimeout(function () {
    if (state.index >= state.steps.length - 1) {
      stop();
    } else {
      next();
    }
  }, dwell);
}

function waitForSelector(sel, cb) {
  if (!sel) {
    cb(null);
    return;
  }
  var start = Date.now();
  function tick() {
    var el = document.querySelector(sel);
    if (el) {
      cb(el);
      return;
    }
    if (Date.now() - start > WAIT_TIMEOUT) {
      cb(null);
      return;
    }
    setTimeout(tick, WAIT_INTERVAL);
  }
  tick();
}

function buildRoot() {
  state.root = document.createElement('div');
  state.root.className = 'tour-root';
  state.overlay = document.createElement('div');
  state.overlay.className = 'tour-overlay';
  state.spotlight = document.createElement('div');
  state.spotlight.className = 'tour-spotlight';
  state.spotlight.style.display = 'none';
  state.card = document.createElement('div');
  state.card.className = 'tour-card';
  state.root.appendChild(state.overlay);
  state.root.appendChild(state.spotlight);
  state.root.appendChild(state.card);
  document.body.appendChild(state.root);

  // Event delegation on the card. Attaching once here is robust against
  // innerHTML rewrites that swap out the actual buttons between steps.
  state.card.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-tour-action]');
    if (!btn || btn.disabled) return;
    var action = btn.getAttribute('data-tour-action');
    if (action === 'exit') stop();
    else if (action === 'prev') prev();
    else if (action === 'next') next();
    else if (action === 'toggle') toggle();
  });

  state.overlay.addEventListener('click', function (e) {
    if (e.target === state.overlay) {
      // Click on the dimmed area pauses but does not exit, so users can
      // explore an element without losing their place.
      toggle();
    }
  });
}

function renderStep(step, el) {
  var card = state.card;
  var n = state.steps.length;
  var i = state.index + 1;
  var isHero = !!step.hero;

  card.className = 'tour-card' + (isHero ? ' hero' : '');
  state.spotlight.style.display = isHero ? 'none' : '';
  state.overlay.className = 'tour-overlay' + (isHero ? ' center' : '');
  state.el = isHero ? null : el;

  if (!isHero && el) {
    var r = el.getBoundingClientRect();
    if (r.top < 0 || r.top > window.innerHeight - 80) {
      el.scrollIntoView({ block: 'center' });
    }
    positionSpotlight(el);
  }

  var heroLogo = isHero ? '<img class="tour-hero-logo" src="logo.jpg" alt="">' : '';

  card.innerHTML =
    heroLogo +
    '<div class="tour-meta">Step ' + i + ' of ' + n + '</div>' +
    '<h3>' + esc(step.title) + '</h3>' +
    '<p>' + esc(step.body) + '</p>' +
    '<div class="tour-controls">' +
    '  <div class="tour-controls-left">' +
    '    <button class="tour-btn tour-btn-ghost" data-tour-action="exit">Exit</button>' +
    '    <button class="tour-btn tour-btn-ghost" data-tour-action="toggle">' + (state.paused ? 'Resume' : 'Pause') + '</button>' +
    '  </div>' +
    '  <div class="tour-controls-right">' +
    '    <button class="tour-btn" data-tour-action="prev"' + (state.index === 0 ? ' disabled' : '') + '>Back</button>' +
    '    <button class="tour-btn tour-btn-primary" data-tour-action="next">' + (step.isFinal ? 'Finish' : 'Next') + '</button>' +
    '  </div>' +
    '</div>' +
    '<div class="tour-progress"><div class="tour-progress-bar"></div></div>';

  state.progressBar = card.querySelector('.tour-progress-bar');

  positionCard(step, el);
}

function updateControls() {
  if (!state.card) return;
  var btn = state.card.querySelector('[data-tour-action="toggle"]');
  if (btn) btn.textContent = state.paused ? 'Resume' : 'Pause';
}

function positionSpotlight(el) {
  var rect = el.getBoundingClientRect();
  var pad = 8;
  var sp = state.spotlight;
  sp.style.top = Math.max(rect.top - pad, 8) + 'px';
  sp.style.left = Math.max(rect.left - pad, 8) + 'px';
  sp.style.width = Math.min(rect.width + pad * 2, window.innerWidth - 16) + 'px';
  sp.style.height = Math.min(rect.height + pad * 2, window.innerHeight - 16) + 'px';
}

// positionCard places the explainer card beside el, or centers it for a hero
// step. A quiet reposition, after a scroll or resize, skips the fade.
function positionCard(step, el, quiet) {
  var card = state.card;
  if (!quiet) card.style.opacity = '0';
  // Defer measurement until after the card has its new innerHTML laid out.
  requestAnimationFrame(function () {
    var w = card.offsetWidth;
    var h = card.offsetHeight;
    var vw = window.innerWidth;
    var vh = window.innerHeight;
    var top, left;
    if (step.hero || !el) {
      top = Math.max((vh - h) / 2, 20);
      left = Math.max((vw - w) / 2, 16);
    } else {
      var rect = el.getBoundingClientRect();
      var pos = step.position || 'right';
      var gap = 22;
      if (pos === 'right' && rect.right + gap + w + 16 < vw) {
        left = rect.right + gap;
        top = clamp(rect.top + rect.height / 2 - h / 2, 16, vh - h - 16);
      } else if (pos === 'left' && rect.left - gap - w > 16) {
        left = rect.left - gap - w;
        top = clamp(rect.top + rect.height / 2 - h / 2, 16, vh - h - 16);
      } else if (pos === 'top' && rect.top - gap - h > 16) {
        top = rect.top - gap - h;
        left = clamp(rect.left + rect.width / 2 - w / 2, 16, vw - w - 16);
      } else if (pos === 'bottom' && rect.bottom + gap + h + 16 < vh) {
        top = rect.bottom + gap;
        left = clamp(rect.left + rect.width / 2 - w / 2, 16, vw - w - 16);
      } else {
        // Fallback: place wherever there is room.
        if (rect.right + gap + w + 16 < vw) {
          left = rect.right + gap;
          top = clamp(rect.top, 16, vh - h - 16);
        } else if (rect.left - gap - w > 16) {
          left = rect.left - gap - w;
          top = clamp(rect.top, 16, vh - h - 16);
        } else {
          top = clamp(rect.bottom + gap, 16, vh - h - 16);
          left = clamp(rect.left, 16, vw - w - 16);
        }
      }
    }
    card.style.top = top + 'px';
    card.style.left = left + 'px';
    card.style.opacity = '1';
  });
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}


function currentPage() {
  return P.page;
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && state.active) stop();
});

// reposition follows the current step's element when the page scrolls or the
// window resizes.
function reposition() {
  if (!state.active) return;
  var step = state.steps[state.index];
  if (!step) return;
  if (state.el && !step.hero) positionSpotlight(state.el);
  positionCard(step, state.el, true);
}

window.addEventListener('resize', reposition);
window.addEventListener('scroll', reposition, true);
