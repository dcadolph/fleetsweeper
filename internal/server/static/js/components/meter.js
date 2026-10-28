// The meter: a labeled value in large type with a caption and a bar filled to
// its share, in place of a doughnut gauge for one number.

import { esc } from '../dom.js';
import { coord } from '../format.js';

// renderMeter returns a meter for label showing value and caption, its bar
// filled to share (0 to 1) in tone (ok, warn, or crit). A null share draws no
// bar, for a reading that is unavailable.
export function renderMeter(label, value, caption, share, tone) {
  const bar = share == null
    ? ''
    : '<svg class="meter-bar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">' +
      `<rect class="ubar-track" width="100" height="6" rx="3"/><rect class="ubar-${esc(tone)}" width="${coord(Math.max(0, Math.min(1, share)) * 100)}" height="6" rx="3"/></svg>`;
  return `<div class="cd meter-card"><div class="eyebrow">${esc(label)}</div>` +
    `<div class="meter-value c-${esc(share == null ? 't3' : tone)}">${esc(value)}</div>` +
    `<div class="note">${esc(caption)}</div>${bar}</div>`;
}
