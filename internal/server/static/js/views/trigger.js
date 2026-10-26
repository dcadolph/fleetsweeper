// Scan triggering from the dashboard and the command palette.

import { apiSend } from '../api.js';

// triggerScan asks for confirmation, then starts a scan of every context.
export async function triggerScan() {
  if (!confirm('Trigger a scan of all contexts?')) return;
  const r = await apiSend('POST', '/scans', { all_contexts: true });
  if (r.ok) alert('Scan triggered. Refresh in a moment to see results.');
  else if (r.status === 401 || r.status === 403) alert('The server requires a token to trigger scans.');
  else if (r.status === 429) alert('A scan is already in progress. Try again in a moment.');
  else alert('Scan request failed: ' + r.status);
}
