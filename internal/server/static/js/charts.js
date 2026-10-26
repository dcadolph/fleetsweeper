// Chart.js wrappers themed from the CSS tokens. Chart is the global the
// vendored chart.min.js defines. Charts made through makeChart are destroyed
// on every navigation.

import { token } from './dom.js';

let instances = [];

// themeCharts points Chart.js defaults at the active theme's text and grid
// colors. Called before every render so a theme switch takes effect.
export function themeCharts() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = token('--text-2');
  Chart.defaults.borderColor = token('--border-soft');
  Chart.defaults.font.family = token('--font-sans');
}

// makeChart creates a chart on the canvas with the given id and tracks it.
export function makeChart(id, cfg) {
  const el = document.getElementById(id);
  if (!el || typeof Chart === 'undefined') return null;
  const c = new Chart(el, cfg);
  instances.push(c);
  return c;
}

// destroyCharts destroys every tracked chart.
export function destroyCharts() {
  instances.forEach((c) => c.destroy());
  instances = [];
}

