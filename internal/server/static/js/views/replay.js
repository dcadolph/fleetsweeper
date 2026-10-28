// The drift replay page: scrub findings across recent scans and rank the
// chronic ones.

import { api } from '../api.js';
import { esc, sevTone, token, byId, emptyState } from '../dom.js';
import { dateTime } from '../format.js';
import { renderBar } from '../shell.js';
import { makeChart } from '../charts.js';
import { onLeave } from '../router.js';

// renderReplay loads the findings timeline and persistence for 24 scans.
export async function renderReplay() {
  renderBar('');
  let tl;
  let pers;
  try {
    [tl, pers] = await Promise.all([api('/findings/timeline?scans=24'), api('/findings/persistence?scans=24')]);
  } catch (e) {
    return '<div class="empty">Error loading replay: ' + esc(e.message) + '</div>';
  }
  const pts = (tl && tl.points) || [];
  if (pts.length < 2) {
    return '<h2>Drift replay</h2>' + emptyState('Drift replay needs at least two scans, and there are ' + pts.length + ' so far.');
  }
  const sets = pts.map((p) => {
    const m = {};
    (p.findings || []).forEach((f) => { m[f.fingerprint] = f; });
    return m;
  });
  const html = '<div class="panel"><h2>Drift replay</h2>' +
    '<p class="sub">Scrub through recent scans to watch findings appear and resolve across the fleet. Press Play to step forward in time. The chronic panel ranks findings by how persistently they recur, an implicit signal of what is a standing problem versus a passing blip.</p>' +
    '<div class="chart-110"><canvas id="replayChart"></canvas></div>' +
    '<div class="replay-controls"><button id="replayPlay" class="btn">Play</button>' +
    `<input id="replaySlider" type="range" min="0" max="${pts.length - 1}" value="${pts.length - 1}" aria-label="Scan">` +
    '<span id="replayStamp" class="mono c-t2"></span></div><div id="replaySummary" class="flex flex-wrap gap-8"></div></div>' +
    '<div class="split-half">' +
    '<div class="panel"><h3 class="mt-0">Findings at this point <span id="replayIdxLabel" class="fs-12 fw-500 c-t3"></span></h3><div id="replayFindings"></div></div>' +
    `<div class="panel"><h3 class="mt-0">Chronic findings <span class="fs-12 fw-500 c-t3">by recurrence across ${pts.length} scans</span></h3><div id="replayChronic"></div></div></div>`;
  return { html, post: () => wire(pts, sets, pers) };
}

// sevRank orders severities critical first.
function sevRank(s) {
  return s === 'critical' ? 0 : s === 'warning' ? 1 : 2;
}

// chip renders one summary tile.
function chip(label, val, tone) {
  return `<div class="mini-stat"><div class="eyebrow">${esc(label)}</div><div class="v c-${tone}">${esc(String(val))}</div></div>`;
}

// row renders one finding, marked new or resolved.
function row(f, mark) {
  const badge = mark === 'new' ? ' <span class="tag bg-ok c-ok">new</span>' : mark === 'resolved' ? ' <span class="tag bg-muted c-t3">resolved</span>' : '';
  return `<div class="rrow ${esc(f.severity)}${mark === 'resolved' ? ' resolved' : ''}"><span class="sev fs-12 c-${sevTone(f.severity)}">${esc(f.severity)}</span>` +
    `<span class="grow fs-12">${esc(f.title)}${badge}</span><span class="mono c-t3">${esc(f.cluster && f.cluster !== 'fleet' ? f.cluster : 'fleet')}</span></div>`;
}

// renderChronic fills the persistence panel.
function renderChronic(pers) {
  const box = byId('replayChronic');
  if (!box) return;
  const list = (pers && pers.findings) || [];
  if (!list.length) {
    box.innerHTML = '<div class="empty">No findings.</div>';
    return;
  }
  const classTone = { chronic: 'crit', intermittent: 'warn' };
  box.innerHTML = `<div class="flex gap-8 mb-8 fs-12"><span class="c-crit">Chronic ${pers.chronic || 0}</span>·<span class="c-warn">Intermittent ${pers.intermittent || 0}</span>·<span class="c-t3">Transient ${pers.transient || 0}</span></div>` +
    list.slice(0, 16).map((p) => {
      const tone = classTone[p.class] || 'muted';
      const share = Math.round(p.fraction * 100);
      return '<div class="rrow"><div class="grow"><div class="flex items-center gap-8">' +
        `<span class="fs-12 c-${tone === 'muted' ? 't3' : tone}">${esc(p.class)}</span>` +
        `<span class="grow fs-12">${esc(p.title)}${p.acked ? ' <span class="fs-12 c-t3" title="Acknowledged">ack</span>' : ''}</span>` +
        `<span class="mono c-${sevTone(p.severity)}">${share}%</span></div>` +
        `<div class="meter"><div class="fill-${tone}" style="width:${share}%"></div></div>` +
        `<div class="note mt-4">present in ${p.present} of ${p.total} scans · streak ${p.streak}</div></div></div>`;
    }).join('');
}

// wire binds the slider, play button, and chart, and registers cleanup.
function wire(pts, sets, pers) {
  const slider = byId('replaySlider');
  const stamp = byId('replayStamp');
  const playBtn = byId('replayPlay');
  const idxLabel = byId('replayIdxLabel');
  let cur = pts.length - 1;
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const radius = () => pts.map((_, i) => (i === cur ? 5 : 2));
  const accent = token('--accent');
  const crit = token('--status-crit');
  const chart = makeChart('replayChart', {
    type: 'line',
    data: {
      labels: pts.map((_, i) => i + 1),
      datasets: [
        { label: 'Total', data: pts.map((p) => p.total), borderColor: accent, backgroundColor: accent + '1f', fill: true, tension: 0.3, pointRadius: radius() },
        { label: 'Critical', data: pts.map((p) => p.critical), borderColor: crit, backgroundColor: crit + '1a', fill: true, tension: 0.3, pointRadius: radius() },
      ],
    },
    options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { labels: { boxWidth: 10 } } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
  });
  renderChronic(pers);

  const paint = () => {
    const p = pts[cur];
    stamp.textContent = 'Scan ' + (cur + 1) + ' of ' + pts.length + ' · ' + dateTime(p.timestamp);
    idxLabel.textContent = '· ' + p.total + ' findings';
    const prev = cur > 0 ? sets[cur - 1] : {};
    const now = sets[cur];
    const appeared = Object.keys(now).filter((fp) => !prev[fp]).length;
    const resolved = Object.keys(prev).filter((fp) => !now[fp]);
    byId('replaySummary').innerHTML = chip('Total', p.total, 't1') + chip('Critical', p.critical, 'crit') + chip('Warning', p.warning, 'warn') +
      chip('Info', p.info, 'info') + chip('Appeared', '+' + appeared, 'ok') + chip('Resolved', '-' + resolved.length, 't3');
    const items = Object.values(now).sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    let out = items.length ? items.map((f) => row(f, prev[f.fingerprint] ? '' : 'new')).join('') : '<div class="empty">No findings at this point.</div>';
    if (resolved.length) out += '<div class="eyebrow my-8">Resolved since previous scan</div>' + resolved.map((fp) => row(prev[fp], 'resolved')).join('');
    byId('replayFindings').innerHTML = out;
    if (chart) {
      chart.data.datasets.forEach((d) => { d.pointRadius = radius(); });
      chart.update('none');
    }
    slider.value = cur;
  };

  let timer = null;
  const stop = () => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    playBtn.textContent = 'Play';
  };
  const start = () => {
    if (reduce) return;
    if (cur >= pts.length - 1) cur = 0;
    playBtn.textContent = 'Pause';
    timer = setInterval(() => {
      if (cur >= pts.length - 1) {
        stop();
        return;
      }
      cur++;
      paint();
    }, 900);
  };
  slider.addEventListener('input', () => {
    cur = parseInt(slider.value, 10) || 0;
    stop();
    paint();
  });
  playBtn.addEventListener('click', () => (timer ? stop() : start()));
  if (reduce) {
    playBtn.disabled = true;
    playBtn.title = 'Autoplay disabled by your reduced-motion preference';
  }
  const onVis = () => { if (document.hidden) stop(); };
  document.addEventListener('visibilitychange', onVis);
  let io = null;
  if (window.IntersectionObserver) {
    io = new IntersectionObserver((es) => es.forEach((e) => { if (!e.isIntersecting) stop(); }));
    io.observe(byId('replayChart'));
  }
  onLeave(() => {
    stop();
    document.removeEventListener('visibilitychange', onVis);
    if (io) io.disconnect();
  });
  paint();
}
