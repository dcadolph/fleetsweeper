// The route table. The sidebar, the command palette, the g-chords, and the
// router all read it, so a page is added in one place.

import { renderDash } from './views/dash.js';
import { renderDetail } from './views/detail.js';
import { renderFindings } from './views/findings.js';
import { renderIncidents } from './views/incidents.js';
import { renderAlerts } from './views/alerts.js';
import { renderScans, renderScanReport } from './views/scans.js';
import { renderTrends } from './views/trends.js';
import { renderCapacity } from './views/capacity.js';
import { renderOutliers } from './views/outliers.js';
import { renderCohorts } from './views/cohorts.js';
import { renderHeatmap } from './views/heatmap.js';
import { renderGlobe } from './views/globe.js';
import { renderDiff } from './views/diff.js';
import { renderReplay } from './views/replay.js';
import { renderClusters } from './views/clusters.js';
import { renderGroups } from './views/groups.js';
import { renderManage } from './views/manage.js';

// ROUTES lists every page. group places it in the sidebar (empty means a
// page reached only by link), abbr is its rail label, and chord is the key
// that follows g to jump to it.
export const ROUTES = [
  { id: 'dash', label: 'Dashboard', group: 'Overview', abbr: 'Db', chord: 'd', render: renderDash },
  { id: 'findings', label: 'Findings', group: 'Findings', abbr: 'Fi', chord: 'f', render: renderFindings },
  { id: 'incidents', label: 'Incidents', group: 'Findings', abbr: 'In', render: renderIncidents },
  { id: 'alerts', label: 'Alerts', group: 'Findings', abbr: 'Al', render: renderAlerts },
  { id: 'outliers', label: 'Outliers', group: 'Findings', abbr: 'Ou', chord: 'o', render: renderOutliers },
  { id: 'clusters', label: 'Clusters', group: 'Clusters', abbr: 'Cl', render: renderClusters },
  { id: 'cohorts', label: 'Cohorts', group: 'Clusters', abbr: 'Co', render: renderCohorts },
  { id: 'groups', label: 'Groups', group: 'Clusters', abbr: 'Gr', render: renderGroups },
  { id: 'capacity', label: 'Capacity and cost', group: 'Clusters', abbr: 'Ca', chord: 'c', render: renderCapacity },
  { id: 'trends', label: 'Trends', group: 'Drift', abbr: 'Tr', chord: 't', render: renderTrends },
  { id: 'replay', label: 'Drift replay', group: 'Drift', abbr: 'Rp', render: renderReplay },
  { id: 'diff', label: 'Scan diff', group: 'Drift', abbr: 'Df', render: renderDiff },
  { id: 'scans', label: 'Scan history', group: 'Drift', abbr: 'Sh', chord: 'h', render: renderScans },
  { id: 'globe', label: 'Globe', group: 'Map', abbr: 'Gl', chord: 'g', render: renderGlobe },
  { id: 'heatmap', label: 'Deviation matrix', group: 'Map', abbr: 'Mx', render: renderHeatmap },
  { id: 'manage', label: 'Add clusters', group: 'Settings', abbr: 'Se', render: renderManage },
  { id: 'detail', label: 'Cluster detail', group: '', render: renderDetail },
  { id: 'scanReport', label: 'Scan report', group: '', render: renderScanReport },
];

// routeById returns the route with the given id, or the dashboard.
export function routeById(id) {
  return ROUTES.find((r) => r.id === id) || ROUTES[0];
}
