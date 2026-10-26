// The drift ledger: the clusters that moved against the fleet norm over a
// window of scans, largest move first, each with its deviation mass over the
// window as a sparkline, the flags it gained or lost, and the field that
// moved the most.

import { esc, clusterHref } from '../dom.js';
import { fmt, linear } from '../viz.js';

// ROWS is how many clusters the ledger lists.
const ROWS = 8;

// sparkline draws a series as a small polyline with its last point marked.
export function sparkline(values) {
  const W = 96;
  const H = 22;
  if (!values || values.length < 2) return '';
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const x = linear(0, values.length - 1, 2, W - 2);
  const y = linear(lo, hi === lo ? lo + 1 : hi, H - 3, 3);
  const pts = values.map((v, i) => x(i).toFixed(1) + ',' + y(v).toFixed(1)).join(' ');
  const last = values.length - 1;
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" aria-hidden="true"><polyline points="${pts}"/>` +
    `<circle cx="${x(last).toFixed(1)}" cy="${y(values[last]).toFixed(1)}" r="2.5"/></svg>`;
}

// flagChips renders gained or lost outlier flags with the scan they changed
// in. scanIndex maps a scan ID to its 1-based position in the window.
function flagChips(flags, gained, scanIndex, total) {
  return (flags || []).map((f) => {
    const at = scanIndex[f.scan];
    const tipText = `${gained ? 'Outside the norm' : 'Back inside the norm'} since scan ${at || '?'} of ${total} (${f.scan}).`;
    return `<span class="chip ${gained ? 'chip-crit' : 'chip-ok'}" data-tip="${esc(tipText)}">${gained ? '+' : '&minus;'} ${esc(f.scanner + '/' + f.field)}</span>`;
  }).join('');
}

// renderDriftLedger returns the ledger's markup. period describes the span
// for the header, e.g. "the last 7 days".
export function renderDriftLedger(ledger, period) {
  const scans = (ledger && ledger.scans) || [];
  const rows = ((ledger && ledger.clusters) || []).slice(0, ROWS);
  const span = scans.length < 2
    ? 'Drift needs at least two scans in the window.'
    : `Across ${scans.length} scans in ${esc(period)}.`;
  if (scans.length < 2 || !rows.length) {
    return `<p class="note">${span}</p>` + (scans.length >= 2 ? '<div class="empty">No cluster moved against the norm in this window.</div>' : '');
  }
  const scanIndex = {};
  scans.forEach((id, i) => { scanIndex[id] = i + 1; });
  let h = `<p class="note mb-8">${span} Deviation mass is how far a cluster sits from the norm across every field; a row needs a changed value or a flag that flipped.</p><div class="ledger">`;
  rows.forEach((r) => {
    const tone = r.mass_delta > 0 ? 'crit' : r.mass_delta < 0 ? 'ok' : 't2';
    const top = (r.fields || [])[0];
    h += '<div class="ledger-row">' +
      `<a class="fw-500 ellipsis" href="${esc(clusterHref(r.cluster))}">${esc(r.cluster)}</a>` +
      `<span class="ledger-spark" data-tip="Deviation mass per scan, oldest first.">${sparkline(r.mass)}</span>` +
      `<span class="mono c-${tone}" data-tip="Deviation mass ${esc(fmt(r.mass_before))} to ${esc(fmt(r.mass_after))}.">${r.mass_delta > 0 ? '+' : ''}${esc(fmt(Math.round(r.mass_delta * 10) / 10))}</span>` +
      `<span class="ledger-flags">${flagChips(r.gained, true, scanIndex, scans.length)}${flagChips(r.lost, false, scanIndex, scans.length)}` +
      (top ? `<span class="fs-12 c-t2" data-tip="The field whose z moved the most.">${esc(top.scanner + '/' + top.field)} <span class="mono">${esc(top.before || '-')} &rarr; ${esc(top.after || '-')}</span></span>` : '') +
      '</span></div>';
  });
  return h + '</div>';
}
