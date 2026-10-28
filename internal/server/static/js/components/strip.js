// Distribution strips: one row per field, every cluster a dot on a shared
// axis, the fleet median as a tick, and the band inside which values are
// normal. Dots past the band are the outliers. String and set fields, which
// have no axis, get a one-line summary of the norm and who misses it.

import { esc, clusterHref } from '../dom.js';
import { linear, jitter, fieldLabel } from '../viz.js';
import { num, coord } from '../format.js';

const W = 800;
const H = 46;
const PAD = 16;

// renderStrips returns markup for a list of distributions. highlight rings
// one cluster's dot. An empty list renders an empty-state line.
export function renderStrips(dists, opts) {
  const o = opts || {};
  if (!dists || !dists.length) return `<div class="empty">${esc(o.empty || 'No distributions to show.')}</div>`;
  return '<div class="strips">' + dists.map((d) => renderStrip(d, o.highlight)).join('') + '</div>';
}

// renderStrip returns one strip row.
export function renderStrip(d, highlight) {
  const flagged = d.values.filter((v) => v.outlier && !v.explained).length;
  const held = d.values.filter((v) => v.explained).length;
  const head = `<div class="strip-head"><span class="strip-name">${esc(fieldLabel(d))}</span>` +
    `<span class="note">${esc(d.kind)} · n=${d.sample_size}${d.scope !== 'fleet' ? ' · ' + esc(d.scope) : ''}${d.limited_sample ? ' · limited sample' : ''}</span>` +
    (held ? `<span class="note strip-held" data-tip="Outside the fleet norm but inside the norm of the cohort they are tagged with, so no finding.">${held} held by their cohort</span>` : '') +
    (flagged ? `<span class="strip-flag">${flagged} outside the norm</span>` : '') + '</div>';
  const body = d.kind === 'numeric' ? numericSVG(d, highlight) : categorical(d, highlight);
  return `<div class="strip" data-field="${esc(fieldLabel(d))}">${head}${body}</div>`;
}

// numericSVG draws the numeric strip.
function numericSVG(d, highlight) {
  const nums = d.values.map((v) => v.number).filter((v) => typeof v === 'number');
  let lo = Math.min(...nums, d.median - d.band);
  let hi = Math.max(...nums, d.median + d.band);
  if (Math.min(...nums) >= 0 && lo < 0) lo = 0;
  if (lo === hi) {
    lo -= 1;
    hi += 1;
  }
  const x = linear(lo, hi, PAD, W - PAD);
  let svg = `<svg class="strip-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(fieldLabel(d))}: median ${esc(num(d.median))}, ${d.values.filter((v) => v.outlier).length} outliers">`;
  if (d.band > 0) {
    const x0 = x(Math.max(lo, d.median - d.band));
    const x1 = x(Math.min(hi, d.median + d.band));
    svg += `<rect class="band" x="${coord(x0)}" y="4" width="${coord(x1 - x0)}" height="${H - 8}"/>` +
      `<line class="band-edge" x1="${coord(x0)}" x2="${coord(x0)}" y1="4" y2="${H - 4}"/>` +
      `<line class="band-edge" x1="${coord(x1)}" x2="${coord(x1)}" y1="4" y2="${H - 4}"/>`;
  }
  svg += `<line class="axis" x1="${PAD}" x2="${W - PAD}" y1="${H - 4}" y2="${H - 4}"/>`;
  svg += `<line class="median" x1="${coord(x(d.median))}" x2="${coord(x(d.median))}" y1="2" y2="${H - 2}"/>`;
  d.values.forEach((v) => {
    if (typeof v.number !== 'number') return;
    const cy = H / 2 + jitter(d.scanner + d.field + v.cluster) * (H / 2 - 10);
    const ring = v.cluster === highlight;
    const state = v.explained ? `, outside the fleet norm, inside cohort ${v.explained}` : v.outlier ? ', outside the norm' : '';
    const tipText = `${v.cluster}: ${num(v.number)}${v.z ? ' (z ' + num(v.z) + ')' : ''}${state}`;
    const cls = v.explained ? ' held' : v.outlier ? ' out' : '';
    svg += `<a href="${esc(clusterHref(v.cluster))}" data-tip="${esc(tipText)}" aria-label="${esc(tipText)}">` +
      `<circle class="dot-pt${cls}${ring ? ' ring' : ''}" cx="${coord(x(v.number))}" cy="${coord(cy)}" r="${ring ? 6 : v.outlier ? 5 : 3.5}"/></a>`;
  });
  svg += '</svg>';
  const scale = `<div class="strip-scale"><span>${esc(num(lo))}</span><span>median ${esc(num(d.median))}${d.band > 0 ? ' ± ' + esc(num(d.band)) : ', MAD 0, no band'}</span><span>${esc(num(hi))}</span></div>`;
  return svg + scale;
}

// categorical summarizes a string or set distribution.
function categorical(d, highlight) {
  const out = d.values.filter((v) => v.outlier && !v.explained);
  const norm = d.kind === 'string'
    ? `mode <span class="mono">${esc(d.mode)}</span> held by ${Math.round((d.mode_share || 0) * 100)}%`
    : `${(d.consensus || []).length} members most clusters have`;
  const chips = out.map((v) => `<a class="chip${v.cluster === highlight ? ' chip-ring' : ''}" href="${esc(clusterHref(v.cluster))}" data-tip="${esc(d.kind === 'set' ? 'missing ' + (v.missing || []).join(', ') : v.text)}">${esc(v.cluster)}</a>`).join('');
  return `<div class="strip-cat"><span>${norm}</span>${out.length ? '<span class="note">outside:</span>' + chips : '<span class="note">everyone agrees</span>'}</div>`;
}
