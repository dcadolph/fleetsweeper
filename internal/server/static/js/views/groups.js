// The groups page: named sets of clusters.

import { api } from '../api.js';
import { esc, clusterHref, emptyState } from '../dom.js';
import { renderBar } from '../shell.js';

// renderGroups lists every group and its members.
export async function renderGroups() {
  renderBar();
  const groups = await api('/groups');
  let h = '<h2>Cluster groups</h2>';
  if (!groups || !groups.length) return h + emptyState('No groups are defined yet, so clusters are compared only as one fleet.', 'Create one with <code>fleetsweeper group create</code>.');
  h += '<div class="g g3">';
  groups.forEach((g) => {
    h += `<div class="cd"><h4 class="mb-4">${esc(g.name)}</h4><div class="fs-12 c-t2 mb-4">${g.clusters ? g.clusters.length : 0} clusters</div>` +
      (g.clusters || []).map((c) => `<div class="fs-12"><a href="${esc(clusterHref(c))}">${esc(c)}</a></div>`).join('') + '</div>';
  });
  return h + '</div>';
}
