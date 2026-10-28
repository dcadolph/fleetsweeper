// The score card: the fleet score at display size with its grade, where the
// score came from, the three terms that cost it the most, the move since the
// last scan with the next scan's projection folded in, and the scan's counts.
// Each number appears once; the ledger behind the score folds away below.

import { esc } from '../dom.js';
import { num, fixed, ago } from '../format.js';

// TERM_LABELS names each score term without its count, so a count shown
// elsewhere on the page is not repeated in a chip.
const TERM_LABELS = {
  'critical-findings': 'Critical findings',
  'warning-findings': 'Warning findings',
  'info-findings': 'Info findings',
  'critical-clusters': 'Critical clusters',
  'degraded-clusters': 'Degraded clusters',
  'version-skew': 'Version skew',
  'worst-node': 'Worst node health',
};

// GRADE_TONES maps a letter grade to a status tone.
const GRADE_TONES = { A: 'ok', B: 'ok', C: 'warn', D: 'crit', F: 'crit' };

// scoreTone returns the status tone of a score.
export function scoreTone(score) {
  return score >= 80 ? 'ok' : score >= 60 ? 'warn' : 'crit';
}

// topTerms returns the n terms that cost the most points, largest first.
export function topTerms(attribution, n) {
  return ((attribution && attribution.terms) || []).filter((t) => t.cost > 0).slice().sort((a, b) => b.cost - a.cost).slice(0, n);
}

// moveLine returns the line for the score's move since the previous scan and
// the projection for the next one, or an empty string when neither is known.
export function moveLine(score, prev, forecast) {
  const parts = [];
  if (prev && typeof prev.score === 'number') {
    const d = score - prev.score;
    const tone = d > 0 ? 'ok' : d < 0 ? 'crit' : 't2';
    const arrow = d > 0 ? '&#9650;' : d < 0 ? '&#9660;' : '&#8211;';
    const text = d === 0 ? 'unchanged' : (d > 0 ? 'up ' : 'down ') + Math.abs(d);
    parts.push(`<span class="c-${tone}" data-tip="Against the previous scan${prev.ts ? ' at ' + esc(prev.ts) : ''}">${arrow} ${text}${prev.ts ? ' since ' + esc(ago(prev.ts)) : ''}</span>`);
  }
  if (forecast && forecast.sufficient && typeof forecast.predicted === 'number') {
    const half = Math.round(Math.max(0, forecast.upper - forecast.lower) / 2);
    const tipText = `Linear fit over the last ${forecast.basis} scans, R² ${fixed(forecast.r_squared || 0, 2)}.`;
    parts.push(`<span class="c-t2" data-tip="${esc(tipText)}">next scan projected ${forecast.predicted}${half > 0 ? ' ± ' + half : ''}</span>`);
  }
  return parts.length ? `<div class="sc-move">${parts.join('<span class="c-t3"> &middot; </span>')}</div>` : '';
}

// renderScoreCard returns the score card for fs, the FleetScore, explained by
// attribution. prev is {score, ts} for the previous scan or null, forecast
// is the fleet score forecast or null, and facts lists {label, value, href,
// action, tip} for the scan's counts.
export function renderScoreCard(fs, attribution, prev, forecast, facts) {
  if (!fs || typeof fs.score !== 'number') return '';
  const tone = scoreTone(fs.score);
  const gradeTone = GRADE_TONES[fs.grade] || 't2';
  let prov = '';
  if (fs.sample_size > 0) {
    prov = `Scored from ${fs.sample_size} cluster${fs.sample_size === 1 ? '' : 's'} across ${fs.dimensions || 0} dimension${fs.dimensions === 1 ? '' : 's'}.`;
    if (fs.excluded_clusters > 0) prov += ` ${fs.excluded_clusters} left out for missing data.`;
  } else {
    prov = fs.headline || 'No clusters scored yet.';
  }
  const chips = topTerms(attribution, 3).map((t) =>
    `<button class="chip chip-btn" data-action="score-term" data-term="${esc(t.term)}" data-tip="${esc(t.reason)}. Click for the findings behind it.">` +
    `${esc(TERM_LABELS[t.term] || t.reason)} <span class="c-crit fw-600">&minus;${esc(num(Math.round(t.cost * 10) / 10))}</span></button>`).join('');
  const factHTML = (facts || []).map((f) => {
    const inner = `<span class="sc-fact-v">${esc(f.value)}</span><span class="sc-fact-l">${esc(f.label)}</span>`;
    const tipAttr = f.tip ? ` data-tip="${esc(f.tip)}"` : '';
    if (f.href) return `<a class="sc-fact" href="${esc(f.href)}"${tipAttr}>${inner}</a>`;
    if (f.action) return `<button class="sc-fact" data-action="${esc(f.action)}"${f.arg ? ` data-arg="${esc(f.arg)}"` : ''}${tipAttr}>${inner}</button>`;
    return `<div class="sc-fact"${tipAttr}>${inner}</div>`;
  }).join('');
  return `<section class="cd score-card" data-tour="fleet-score" aria-label="Fleet score">` +
    `<div class="sc-main" data-tip="Fleet score, 0 to 100. It starts at 100 and each term below takes points away.">` +
    `<span class="sc-num c-${tone}">${fs.score}</span><span class="sc-grade c-${gradeTone}" aria-label="Grade ${esc(fs.grade)}">${esc(fs.grade)}</span>` +
    '<span class="eyebrow">Fleet score</span></div>' +
    `<div class="sc-side">${moveLine(fs.score, prev, forecast)}<div class="sc-prov">${esc(prov)}</div>` +
    (chips ? `<div class="chips" aria-label="What cost the most points">${chips}</div>` : '') +
    (factHTML ? `<div class="sc-facts">${factHTML}</div>` : '') + '</div></section>';
}
