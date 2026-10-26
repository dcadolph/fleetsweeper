// The globe: clusters placed on a 3D earth with a side panel listing them
// worst first, status filters, search, a critical-cluster tour, and a
// day-night terminator.

import { api } from '../api.js';
import { esc, byId, toneColor, statusTone } from '../dom.js';
import { renderBar } from '../shell.js';
import { nav, onLeave } from '../router.js';
import { on, onChange } from '../actions.js';
import { findingsHref } from './findings.js';

const STATUSES = ['critical', 'degraded', 'busy', 'healthy'];
const SOURCE_LABELS = { manual: 'manual override', configmap: 'in-cluster ConfigMap', annotation: 'in-cluster annotation', auto: 'auto-detected' };

const state = {
  points: [],
  filter: { healthy: true, busy: true, degraded: true, critical: true },
  selected: null,
  search: '',
  globe: null,
  autoRotate: true,
  tourTimer: null,
};

// norm folds the legacy strained status into degraded.
function norm(status) {
  return status === 'strained' ? 'degraded' : status;
}

// colorOf returns the theme color of a cluster status.
export function colorOf(status) {
  return toneColor(statusTone(norm(status)));
}

// pointSize returns a marker radius growing with the cluster's deviation mass relative to the
// largest in pts, so the clusters furthest from their norm stand out.
export function pointSize(p, pts) {
  const top = Math.max(1, ...pts.map((x) => x.deviation_mass || 0));
  return 0.3 + 0.7 * Math.sqrt((p.deviation_mass || 0) / top);
}

// ringsFor returns the pulsing rings: one source per cluster with a field outside the norm, its
// rings spaced closer the more fields flag it, in the cluster's status color.
export function ringsFor(pts) {
  return pts.filter((p) => p.outlier_fields > 0).map((p) => ({
    lat: p.lat, lng: p.lng, maxR: 4 + Math.min(p.outlier_fields, 4), propagationSpeed: 2,
    repeatPeriod: 2400 / Math.min(p.outlier_fields, 4), color: colorOf(p.status),
  }));
}

// ringColor fades a ring from its color to transparent as it spreads.
export function ringColor(d) {
  const hex = (d.color || '#f85149').replace('#', '');
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
  return (t) => `rgba(${r},${g},${b},${1 - t})`;
}

// renderGlobe builds the page shell; initGlobe mounts the scene.
export async function renderGlobe() {
  renderBar('<input type="search" class="input-w" placeholder="Search clusters..." data-change="globe-search" aria-label="Search clusters">' +
    '<button class="btn" data-action="globe-tour" id="globeTourBtn">Tour critical</button>' +
    `<button class="btn" data-action="globe-rotate" id="globeRotateBtn">${state.autoRotate ? 'Pause rotation' : 'Resume rotation'}</button>`);
  const h = '<h2>Fleet globe</h2><p class="sub">Click a cluster on the globe or in the right panel to fly there and see actions.</p>' +
    '<div id="globeFilter" class="flex flex-wrap gap-6 mb-8"></div>' +
    '<div class="split-side"><div id="globe-wrap" class="globe-wrap"></div>' +
    '<div class="globe-side"><div id="globe-summary" class="sect">Loading...</div><div id="globe-action" class="sect action hidden"></div>' +
    '<div class="sect eyebrow">Clusters furthest from the norm first</div><div id="globe-list" class="globe-list"></div></div></div>' +
    '<div class="legend">' + STATUSES.slice().reverse().map((s) => `<span><span class="dot fill-${statusTone(s)}"></span> ${s}</span>`).join('') +
    '<span>size: deviation from the norm</span><span>rings: fields outside the norm</span>' +
    '<span class="ml-auto"><span id="globe-located-count">0</span> placed &middot; <span id="globe-unlocated-count">0</span> unplaced</span></div>' +
    '<div id="globe-unlocated" class="note mt-4"></div>';
  return { html: h, post: initGlobe };
}

// showError replaces the globe with a visible error and its detail.
function showError(wrap, msg, detail) {
  wrap.innerHTML = `<div class="empty"><div class="fs-14 c-crit mb-8">${esc(msg)}</div><pre class="json">${esc(detail || '')}</pre></div>`;
}

// loadGlobeLib loads the vendored globe.gl once.
export function loadGlobeLib() {
  if (window.Globe) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = '/vendor/globe.gl.min.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('failed to load globe.gl'));
    document.head.appendChild(s);
  });
}

// initGlobe fetches placements and mounts the scene. Every await is followed
// by a check that the page is still mounted, so leaving mid-load is safe.
async function initGlobe() {
  let wrap = byId('globe-wrap');
  try {
    await loadGlobeLib();
  } catch (e) {
    if (wrap) showError(wrap, 'Could not load the globe library.', e.message);
    return;
  }
  let resp;
  try {
    resp = await api('/geo');
  } catch (e) {
    wrap = byId('globe-wrap');
    if (wrap) showError(wrap, 'Could not fetch /api/geo.', e.message);
    return;
  }
  wrap = byId('globe-wrap');
  if (!wrap) return;
  const unlocated = (resp && resp.unlocated) || [];
  byId('globe-unlocated-count').textContent = String(unlocated.length);
  if (unlocated.length) {
    byId('globe-unlocated').textContent = 'Unplaced: ' + unlocated.slice(0, 10).join(', ') + (unlocated.length > 10 ? ' (and ' + (unlocated.length - 10) + ' more)' : '');
  }
  if (!resp || !resp.points || !resp.points.length) {
    wrap.innerHTML = '<div class="empty">No clusters with locations. Run <code>fleetsweeper location set &lt;cluster&gt; --lat X --lng Y --site "..."</code> or scan a cluster with cloud region labels.</div>';
    return;
  }
  const pts = resp.points;
  state.points = pts;
  state.selected = null;
  byId('globe-located-count').textContent = String(pts.length);

  let globe;
  try {
    globe = window.Globe()(wrap)
      .globeImageUrl('/vendor/earth-night.jpg')
      .bumpImageUrl('/vendor/earth-topology.png')
      .backgroundColor('rgba(0,0,0,0)')
      .atmosphereColor(toneColor('info'))
      .atmosphereAltitude(0.18)
      .pointLat('lat').pointLng('lng').pointColor('color')
      .pointAltitude((d) => (d.status === 'critical' ? 0.06 : 0.02))
      .pointRadius('size')
      .pointLabel((d) => '<div class="globe-tip">' +
        `<div class="fw-600 mb-4">${esc(d.cluster)}</div><div class="c-t2">${esc(d.status)} &middot; ${esc(SOURCE_LABELS[d.source] || d.source)}</div>` +
        (d.region ? `<div class="c-t2">${esc(d.region)}${d.provider ? ' &middot; ' + esc(d.provider) : ''}</div>` : '') +
        (d.critical ? `<div class="c-crit">${d.critical} critical</div>` : '') +
        (d.warning ? `<div class="c-warn">${d.warning} warning</div>` : '') +
        `<div class="c-t2">deviation ${(d.mass || 0).toFixed(1)}${d.fields ? ' &middot; ' + d.fields + ' field' + (d.fields === 1 ? '' : 's') + ' outside the norm' : ''}</div></div>`)
      .onPointClick((d) => selectCluster(d.cluster))
      .ringColor(ringColor)
      .ringMaxRadius('maxR').ringPropagationSpeed('propagationSpeed').ringRepeatPeriod('repeatPeriod')
      .labelLat('lat').labelLng('lng').labelText('text').labelSize('size')
      .labelColor((d) => d.color).labelDotRadius(0.25).labelResolution(2);
  } catch (e) {
    showError(wrap, 'Globe failed to initialize.', e.message);
    return;
  }
  globe.width(wrap.clientWidth).height(640);
  globe.controls().autoRotate = state.autoRotate;
  globe.controls().autoRotateSpeed = 0.4;
  globe.controls().enableDamping = true;
  state.globe = globe;
  applyLayers();

  const worst = pts.find((p) => p.status === 'critical') || pts[0];
  const focus = setTimeout(() => globe.pointOfView({ lat: worst.lat, lng: worst.lng, altitude: 2.2 }, 1500), 400);
  const onResize = () => { if (state.globe) state.globe.width(wrap.clientWidth); };
  window.addEventListener('resize', onResize);
  const sun = dayNight(globe);
  onLeave(() => {
    clearTimeout(focus);
    clearInterval(sun);
    stopTour();
    window.removeEventListener('resize', onResize);
    if (state.globe && state.globe._destructor) state.globe._destructor();
    state.globe = null;
  });
  renderSide();
}

// applyLayers refreshes points, rings, and labels for the active filter.
function applyLayers() {
  if (!state.globe) return;
  const pts = state.points.filter((p) => state.filter[norm(p.status)]);
  state.globe
    .pointsData(pts.map((p) => ({
      lat: p.lat, lng: p.lng,
      size: pointSize(p, state.points) + (state.selected === p.cluster ? 0.15 : 0),
      color: colorOf(p.status), cluster: p.cluster, status: p.status, source: p.source, region: p.region, provider: p.provider,
      critical: p.critical_findings, warning: p.warning_findings, mass: p.deviation_mass, fields: p.outlier_fields,
    })))
    .ringsData(ringsFor(pts))
    .labelsData(pts.filter((p) => p.source !== 'auto' || p.status === 'critical' || state.selected === p.cluster).map((p) => ({
      lat: p.lat, lng: p.lng, text: p.site || p.cluster,
      size: state.selected === p.cluster ? 0.55 : p.source !== 'auto' ? 0.45 : 0.35,
      color: p.status === 'critical' ? '#ffb4b4' : '#e6edf3',
    })));
}

// renderSide redraws the filter chips, the summary, and the cluster list.
function renderSide() {
  const filterEl = byId('globeFilter');
  if (!filterEl) return;
  const counts = { critical: 0, degraded: 0, busy: 0, healthy: 0 };
  state.points.forEach((p) => { if (counts[norm(p.status)] !== undefined) counts[norm(p.status)]++; });
  filterEl.innerHTML = STATUSES.map((s) => `<button class="btn filter-btn${state.filter[s] ? ' c-' + statusTone(s) : ' off'}" data-action="globe-filter" data-status="${s}" aria-pressed="${state.filter[s]}">${s} ${counts[s]}</button>`).join('');
  byId('globe-summary').innerHTML = STATUSES.map((s) => `<div class="flex between"><span>${s[0].toUpperCase() + s.slice(1)}</span><span class="c-${statusTone(s)} fw-600">${counts[s]}</span></div>`).join('');

  const q = state.search.toLowerCase();
  const visible = state.points.filter((p) => state.filter[norm(p.status)] &&
    (!q || [p.cluster, p.site, p.region, p.city].some((v) => (v || '').toLowerCase().includes(q))))
    .sort((a, b) => ((b.deviation_mass || 0) - (a.deviation_mass || 0)) || (a.cluster || '').localeCompare(b.cluster || ''));
  const list = byId('globe-list');
  list.innerHTML = visible.length ? visible.map((p) => `<button class="globe-row${state.selected === p.cluster ? ' sel' : ''}" data-action="globe-select" data-cluster="${esc(p.cluster)}">` +
    `<span class="dot fill-${statusTone(norm(p.status))}"></span><span class="grow"><span class="fs-12 fw-500 ellipsis">${esc(p.cluster)}</span>` +
    `<br><span class="fs-12 c-t3 ellipsis">${esc(p.site || p.city || p.region || '')}</span></span>` +
    (p.critical_findings ? `<span class="fs-12 c-crit fw-600">${p.critical_findings}</span>` : '') + '</button>').join('')
    : '<div class="empty">No clusters match your filters.</div>';
}

// selectCluster flies to a cluster and shows its action panel.
function selectCluster(cluster) {
  const p = state.points.find((x) => x.cluster === cluster);
  const act = byId('globe-action');
  if (!p || !act) return;
  state.selected = cluster;
  if (state.globe) state.globe.pointOfView({ lat: p.lat, lng: p.lng, altitude: 1.6 }, 900);
  const s = norm(p.status);
  act.classList.remove('hidden');
  act.innerHTML = `<div class="flex items-center gap-8 mb-4"><span class="dot dot-lg fill-${statusTone(s)}"></span><span class="fw-600">${esc(p.cluster)}</span></div>` +
    `<div class="fs-12 c-t2 mb-8">${esc(s)} &middot; ${esc(p.source || 'auto')}${p.region ? ' &middot; ' + esc(p.region) : ''}${p.site ? ' &middot; ' + esc(p.site) : p.city ? ' &middot; ' + esc(p.city) : ''}</div>` +
    (p.critical_findings ? `<div class="fs-12 c-crit">${p.critical_findings} critical findings</div>` : '') +
    (p.warning_findings ? `<div class="fs-12 c-warn mb-4">${p.warning_findings} warning findings</div>` : '') +
    '<div class="flex flex-wrap gap-6 mt-8">' +
    `<button class="btn btn-ac" data-action="globe-drill" data-cluster="${esc(p.cluster)}">Open cluster page</button>` +
    `<a class="btn" href="${esc(findingsHref({ cluster: p.cluster }))}">Findings for this cluster</a>` +
    `<button class="btn" data-action="copy" data-copy="${esc('kubectl --context ' + p.cluster + ' get nodes')}">Copy kubectl</button></div>`;
  applyLayers();
  renderSide();
}

// stopTour ends the critical-cluster tour.
function stopTour() {
  if (state.tourTimer) clearInterval(state.tourTimer);
  state.tourTimer = null;
  const btn = byId('globeTourBtn');
  if (btn) btn.textContent = 'Tour critical';
}

// dayNight puts the globe's light at the sub-solar point and refreshes it
// each minute. It returns the interval to clear on leave.
function dayNight(globe) {
  if (typeof globe.lights !== 'function' || typeof globe.getCoords !== 'function') return null;
  const update = () => {
    const lights = globe.lights();
    if (!lights || !lights.length) return;
    const now = new Date();
    let lng = (12 - (now.getUTCHours() + now.getUTCMinutes() / 60)) * 15;
    if (lng < -180) lng += 360;
    if (lng > 180) lng -= 360;
    const doy = Math.floor((now - Date.UTC(now.getUTCFullYear(), 0, 0)) / 86400000);
    const decl = 23.44 * Math.sin(2 * Math.PI * (doy - 81) / 365);
    lights.forEach((l) => {
      if (l.type === 'DirectionalLight') {
        const c = globe.getCoords(decl, lng, 1);
        l.position.set(c.x, c.y, c.z);
        l.intensity = 1.1;
      } else if (l.type === 'AmbientLight') {
        l.intensity = 0.28;
      }
    });
  };
  update();
  return setInterval(() => { if (!document.hidden) update(); }, 60000);
}

on('globe-filter', (btn) => {
  state.filter[btn.dataset.status] = !state.filter[btn.dataset.status];
  renderSide();
  applyLayers();
});
on('globe-select', (btn) => selectCluster(btn.dataset.cluster));
on('globe-drill', (btn) => nav('detail', { cluster: btn.dataset.cluster }));
on('globe-rotate', (btn) => {
  state.autoRotate = !state.autoRotate;
  if (state.globe) state.globe.controls().autoRotate = state.autoRotate;
  btn.textContent = state.autoRotate ? 'Pause rotation' : 'Resume rotation';
});
on('globe-tour', (btn) => {
  if (state.tourTimer) {
    stopTour();
    return;
  }
  const criticals = state.points.filter((p) => p.status === 'critical');
  if (!criticals.length) {
    btn.textContent = 'No critical clusters';
    setTimeout(() => { btn.textContent = 'Tour critical'; }, 1500);
    return;
  }
  btn.textContent = 'Stop tour';
  let i = 0;
  const step = () => selectCluster(criticals[i++ % criticals.length].cluster);
  step();
  state.tourTimer = setInterval(step, 3500);
});
onChange('globe-search', (input) => {
  state.search = input.value || '';
  renderSide();
});
