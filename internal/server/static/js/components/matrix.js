// The deviation matrix: clusters as rows in the cohort leaf order, fields as
// columns most deviant first, each cell colored by how far the cluster sits
// from the norm. Cohorts read as blocks because the rows are seriated.

import { esc } from '../dom.js';
import { zLevel, fieldLabel, cohortTones } from '../viz.js';
import { fixed } from '../format.js';

// renderMatrix returns the matrix markup. dists are fleet distributions;
// order lists clusters in leaf order; cohortOf maps a cluster to its cohort.
export function renderMatrix(dists, order, cohortOf) {
  const cohortTone = cohortTones(Object.values(cohortOf));
  const cols = dists.filter((d) => d.values.length);
  if (!cols.length || !order.length) return '<div class="empty">No distributions to plot.</div>';
  const index = cols.map((d) => {
    const m = new Map();
    d.values.forEach((v) => m.set(v.cluster, v));
    return m;
  });
  let h = `<div class="matrix" role="grid" aria-label="Deviation matrix" style="--cols:${cols.length}">`;
  h += '<div class="mx-corner"></div>' + cols.map((d) =>
    `<div class="mx-col" role="columnheader" title="${esc(fieldLabel(d))}"><span>${esc(fieldLabel(d))}</span></div>`).join('');
  let prev = null;
  order.forEach((c) => {
    const cohort = cohortOf[c] || '';
    const start = cohort !== prev;
    prev = cohort;
    h += `<div class="mx-row-head ${cohortTone(cohort)}${start ? ' mx-start' : ''}" role="rowheader" title="${esc(cohort)}">` +
      `${start ? `<span class="mx-cohort">${esc(cohort)}</span>` : ''}<span class="ellipsis">${esc(c)}</span></div>`;
    cols.forEach((d, i) => {
      const v = index[i].get(c);
      if (!v) {
        h += `<div class="mx-cell mx-none${start ? ' mx-start' : ''}" role="gridcell" data-tip="${esc(c + ' · ' + fieldLabel(d) + ': no reading')}"></div>`;
        return;
      }
      const level = v.explained ? 0 : d.kind === 'numeric' ? zLevel(v.z) : v.outlier ? 5 : 0;
      const tipText = `${c} · ${fieldLabel(d)}: ${v.number != null ? v.number : v.text || (v.missing ? 'missing ' + v.missing.length : '')}${v.z ? ' (z ' + fixed(v.z, 1) + ')' : ''}${v.explained ? ', inside cohort ' + v.explained : ''}`;
      h += `<button class="mx-cell z${level}${v.outlier && !v.explained ? ' mx-out' : ''}${start ? ' mx-start' : ''}" role="gridcell" data-action="matrix-cell" ` +
        `data-col="${i}" data-cluster="${esc(c)}" data-tip="${esc(tipText)}" aria-label="${esc(tipText)}"></button>`;
    });
  });
  h += '</div><div class="legend mt-8"><span>|z| below 1</span>' +
    [0, 1, 2, 3, 4, 5].map((l) => `<span aria-hidden="true" class="swatch z${l}"></span>`).join('') + '<span>10 or more</span><span aria-hidden="true" class="swatch mx-none"></span><span>no reading</span><span class="ml-auto">rows grouped by cohort</span></div>';
  return h;
}
