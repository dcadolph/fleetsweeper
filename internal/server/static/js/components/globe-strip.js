// The globe strip: the fleet globe at strip height on the dashboard, turning
// slowly with the worst cluster in view, encoded as on the Globe page: size by
// deviation from the norm, rings for fields outside it, color by status. It does
// not take the pointer; a click anywhere opens the full Globe view.

import { api } from '../api.js';
import { esc, byId, toneColor } from '../dom.js';
import { onLeave } from '../router.js';
import { loadGlobeLib, colorOf, pointSize, ringsFor, ringColor } from '../views/globe.js';

// STRIP_HEIGHT is the strip's height in pixels.
export const STRIP_HEIGHT = 280;

// renderGlobeStrip returns the strip's markup.
export function renderGlobeStrip() {
  return '<div class="globe-strip" data-href="#/globe" role="link" tabindex="0" aria-label="Open the fleet globe">' +
    '<div id="globeStrip" class="globe-strip-canvas"></div><span class="globe-strip-cta">Open the globe &rarr;</span></div>';
}

// stripMessage replaces the strip's canvas with a short note.
function stripMessage(wrap, text) {
  wrap.innerHTML = `<div class="globe-strip-note">${esc(text)}</div>`;
}

// mountGlobeStrip loads the globe library and the cluster placements and
// mounts the scene. Leaving the page mid-load is safe: every await is
// followed by a check that the strip is still in the document.
export async function mountGlobeStrip() {
  let wrap = byId('globeStrip');
  if (!wrap) return;
  let resp;
  try {
    [, resp] = await Promise.all([loadGlobeLib(), api('/geo')]);
  } catch (e) {
    wrap = byId('globeStrip');
    if (wrap) stripMessage(wrap, 'The globe could not load: ' + e.message);
    return;
  }
  wrap = byId('globeStrip');
  if (!wrap) return;
  const pts = (resp && resp.points) || [];
  if (!pts.length) {
    stripMessage(wrap, 'No cluster has a location yet. Open the globe to place them.');
    return;
  }
  let globe;
  try {
    globe = window.Globe()(wrap)
      .globeImageUrl('/vendor/earth-night.jpg')
      .backgroundColor('rgba(0,0,0,0)')
      .atmosphereColor(toneColor('info'))
      .atmosphereAltitude(0.15)
      .pointLat('lat').pointLng('lng')
      .pointColor((d) => colorOf(d.status))
      .pointAltitude((d) => (d.status === 'critical' ? 0.06 : 0.02))
      .pointRadius((d) => pointSize(d, pts))
      .pointsData(pts)
      .ringColor(ringColor)
      .ringMaxRadius('maxR').ringPropagationSpeed('propagationSpeed').ringRepeatPeriod('repeatPeriod')
      .ringsData(ringsFor(pts))
      .width(wrap.clientWidth)
      .height(STRIP_HEIGHT);
  } catch (e) {
    stripMessage(wrap, 'The globe could not start: ' + e.message);
    return;
  }
  const controls = globe.controls();
  controls.enabled = false;
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.5;
  const worst = pts.find((p) => p.status === 'critical') || pts[0];
  globe.pointOfView({ lat: worst.lat, lng: worst.lng, altitude: 2.1 });
  const onResize = () => globe.width(wrap.clientWidth);
  window.addEventListener('resize', onResize);
  onLeave(() => {
    window.removeEventListener('resize', onResize);
    if (globe._destructor) globe._destructor();
  });
}
