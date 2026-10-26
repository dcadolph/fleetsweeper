// The outliers page: clusters that deviate from the fleet norm.

import { api } from '../api.js';
import { esc, clusterHref, sevTone } from '../dom.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';

// renderOutliers lists the latest scan's outliers and their findings.
export async function renderOutliers() {
  renderBar();
  const data = await api('/outliers');
  let h = '<h2>Outlier detection</h2><p class="sub">Clusters that deviate from fleet norms (latest scan)</p>';
  if (!data.outliers || !data.outliers.length) {
    h += '<div class="empty">No outliers detected. Fleet is consistent.</div>';
  } else {
    h += '<div class="tw"><table><thead><tr><th>Severity</th><th>Cluster</th><th>Scanner</th><th>Field</th><th>Value</th><th>Fleet norm</th>' +
      '<th data-tip="Modified z-score (standard deviations from median)">Deviation</th></tr></thead><tbody>';
    data.outliers.forEach((o) => {
      h += `<tr><td class="c-${sevTone(o.severity)}">${esc(o.severity)}</td><td class="fw-500"><a href="${esc(clusterHref(o.cluster))}">${esc(o.cluster)}</a></td>` +
        `<td>${esc(o.scanner)}</td><td>${esc(o.field)}</td><td class="mono">${esc(o.value)}</td><td class="mono">${esc(o.fleet_norm)}</td>` +
        `<td class="mono">${o.deviation ? o.deviation.toFixed(1) : ''}</td></tr>`;
    });
    h += '</tbody></table></div>';
  }
  if (data.findings && data.findings.length) h += '<h3>Findings from outlier analysis</h3>' + data.findings.map(renderFinding).join('');
  return h;
}
