// The score waterfall: 100 points stepping down by each cost term to the
// score, with the cost a cap forgave drawn hatched, and the rules that cost
// the most points beside it.

import { esc, token } from '../dom.js';
import { makeChart } from '../charts.js';
import { num, fixed } from '../format.js';

// hatch returns a diagonal-line canvas pattern in color.
function hatch(color) {
  const c = document.createElement('canvas');
  c.width = 8;
  c.height = 8;
  const ctx = c.getContext('2d');
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(0, 8);
  ctx.lineTo(8, 0);
  ctx.stroke();
  return ctx.createPattern(c, 'repeat');
}

// waterfallSteps returns the floating bar spans for the terms, largest cost
// first, and the score bar. Each step starts where the last one ended.
export function waterfallSteps(attribution, score) {
  const terms = (attribution.terms || []).slice().sort((a, b) => b.cost - a.cost);
  let level = 100;
  const steps = terms.map((t) => {
    const from = level;
    level -= t.cost;
    return { label: t.reason, term: t.term, cost: t.cost, span: [from, level], forgiven: t.raw > t.cost ? [level, Math.max(0, level - (t.raw - t.cost))] : null };
  });
  steps.push({ label: 'Score', term: 'score', cost: score, span: [0, score], forgiven: null });
  return steps;
}

// renderWaterfall returns the markup the charts mount into.
export function renderWaterfall(attribution) {
  const rules = Object.entries(attribution.by_rule || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return '<div class="g g2"><div class="chc"><h4>Where the points went</h4><div class="chart-260"><canvas id="wfChart"></canvas></div>' +
    '<p class="note mt-4">Hatched bars are cost a cap forgave. Click a findings bar to list those findings.</p></div>' +
    '<div class="chc"><h4>Rules that cost the most</h4>' + (rules.length
      ? '<div class="rule-bars">' + rules.map(([rule, cost]) => `<button class="rule-bar" data-action="rule-findings" data-rule="${esc(rule)}" data-tip="${esc(num(cost))} points">` +
        `<span class="ellipsis">${esc(rule)}</span><span class="rule-fill" style="--w:${fixed(Math.max(2, (cost / rules[0][1]) * 100), 0)}%"></span><span class="mono">${esc(num(cost))}</span></button>`).join('') + '</div>'
      : '<div class="empty">No rule costs points.</div>') + '</div></div>';
}

// mountWaterfall draws the waterfall chart; onTerm is called with a term
// name when a bar is clicked.
export function mountWaterfall(attribution, score, onTerm) {
  const steps = waterfallSteps(attribution, score);
  const crit = token('--status-crit');
  const ok = token('--status-ok');
  makeChart('wfChart', {
    type: 'bar',
    data: {
      labels: steps.map((s) => s.label),
      datasets: [
        { label: 'Cost', data: steps.map((s) => s.span), backgroundColor: steps.map((s) => (s.term === 'score' ? ok : crit + 'b3')), borderRadius: 3, grouped: false },
        { label: 'Forgiven by a cap', data: steps.map((s) => s.forgiven), backgroundColor: hatch(crit), borderColor: crit, borderWidth: 1, borderRadius: 3, grouped: false },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (c) => {
              const s = steps[c.dataIndex];
              if (c.datasetIndex === 1) return 'forgiven by a cap: ' + num(s.forgiven[0] - s.forgiven[1]) + ' points';
              return s.term === 'score' ? 'score ' + s.cost : '-' + num(s.cost) + ' points';
            },
          },
        },
      },
      scales: { x: { min: 0, max: 100 }, y: { grid: { display: false } } },
      onClick: (_, els) => {
        if (els.length) onTerm(steps[els[0].index].term);
      },
    },
  });
}
