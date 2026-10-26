// The deviation matrix page: clusters by fields, seriated so cohorts read as
// blocks. Clicking a cell opens that field's strip with the cluster ringed.

import { api } from '../api.js';
import { byId } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderMatrix } from '../components/matrix.js';
import { renderStrip } from '../components/strip.js';
import { on } from '../actions.js';

let dists = [];

// renderHeatmap builds the matrix for the latest scan.
export async function renderHeatmap() {
  renderBar('');
  const [resp, mapResp] = await Promise.all([api('/distributions'), api('/cohorts/map')]);
  dists = resp.distributions || [];
  const points = (mapResp.map && mapResp.map.points) || [];
  const cohortOf = {};
  points.forEach((p) => { cohortOf[p.cluster] = p.cohort; });
  const order = (mapResp.map && mapResp.map.leaf_order) || points.map((p) => p.cluster);
  return '<h2>Deviation matrix</h2><p class="sub">Every cluster against every field the detectors measured, darker the further from the fleet median. Rows follow the cohort map, so a cohort that drifts together shows as a block. Click a cell for the field\'s strip.</p>' +
    renderMatrix(dists, order, cohortOf) + '<div id="matrixStrip" class="mt-12"></div>';
}

on('matrix-cell', (cell) => {
  const d = dists[Number(cell.dataset.col)];
  const box = byId('matrixStrip');
  if (!d || !box) return;
  box.innerHTML = renderStrip(d, cell.dataset.cluster);
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});
