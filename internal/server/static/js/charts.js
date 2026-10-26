// Chart.js wrappers themed from the CSS tokens. Chart is the global the
// vendored chart.min.js defines. Charts made through makeChart are destroyed
// on every navigation.

import { token, toneColor, threshTone } from './dom.js';

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

// centerText returns a plugin that writes a big value and a small caption in
// the middle of a doughnut.
function centerText(id, big, small, offset) {
  return {
    id: 'center_' + id,
    afterDraw(chart) {
      const { ctx } = chart;
      const w = chart.width / 2;
      const h = chart.height / 2 + offset;
      ctx.save();
      ctx.textAlign = 'center';
      ctx.fillStyle = token('--text-1');
      ctx.font = '700 18px ' + token('--font-sans');
      ctx.fillText(big, w, h);
      ctx.font = '12px ' + token('--font-sans');
      ctx.fillStyle = token('--text-2');
      ctx.fillText(small, w, h + 16);
      ctx.restore();
    },
  };
}

// percentDoughnut draws a full doughnut of a percentage with the value in
// the middle.
export function percentDoughnut(id, val, label) {
  makeChart(id, {
    type: 'doughnut',
    data: { labels: [label, 'Free'], datasets: [{ data: [val, 100 - val], backgroundColor: [toneColor(threshTone(val)), token('--surface-3')], borderWidth: 0 }] },
    options: { cutout: '72%', plugins: { legend: { display: false } } },
    plugins: [centerText(id, Math.round(val) + '%', label, 8)],
  });
}

// partDoughnut draws a two-part doughnut, good part first, with "good/total"
// in the middle and a legend underneath.
export function partDoughnut(id, labels, good, bad, caption, badTone) {
  makeChart(id, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: [good, bad], backgroundColor: [toneColor('ok'), toneColor(badTone)], borderWidth: 0 }] },
    options: { cutout: '72%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 6 } } } },
    plugins: [centerText(id, good + '/' + (good + bad), caption, 0)],
  });
}
