// Scan triggering from the dashboard and the command palette.

import { send } from '../auth.js';
import { openDrawer } from '../components/drawer.js';
import { toast } from '../components/toast.js';
import { isLive } from '../live.js';

// triggerScan confirms in a drawer, then starts a scan of every context.
export function triggerScan() {
  openDrawer({
    title: 'Scan every context',
    body: '<p class="note">The server scans every kubeconfig context it can reach. A scan already running holds the slot until it finishes.</p>',
    actions: [{
      label: 'Start scan',
      tone: 'primary',
      run: async () => {
        if (!await send('POST', '/scans', { all_contexts: true }, 'Scan')) return false;
        toast(isLive() ? 'Scan started. This page updates when it finishes.' : 'Scan started. Turn on Live or reload when it finishes.', 'ok');
        return true;
      },
    }],
  });
}
