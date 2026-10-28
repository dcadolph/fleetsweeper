// The drift view: which clusters moved against the norm over a window of scans,
// from /api/drift, then the findings that appeared and resolved between the
// window's first and last scans. The window is the last N scans or a date
// range, kept in the URL as #/drift?scans=10 or #/drift?since=...&until=...

import { api } from '../api.js';
import { esc, clusterHref, scanHref, emptyState } from '../dom.js';
import { dateTime } from '../format.js';
import { renderBar } from '../shell.js';
import { renderDriftLedger, driftMarkdown } from '../components/drift-ledger.js';
import { P, nav } from '../router.js';
import { on } from '../actions.js';

// WINDOWS lists the scan counts the window picker offers.
const WINDOWS = [2, 5, 10, 24];

// windowOf reads the window from the URL query.
function windowOf(q) {
  if (q.since || q.until) return { since: q.since || '', until: q.until || '' };
  return { scans: Math.min(50, Math.max(2, Number(q.scans) || 10)) };
}

// renderDrift builds the drift view for the window in the URL.
export async function renderDrift() {
  renderBar();
  const w = windowOf(P.query || {});
  const params = new URLSearchParams();
  if (w.scans) {
    params.set('scans', w.scans);
  } else {
    if (w.since) params.set('since', w.since + 'T00:00:00Z');
    if (w.until) params.set('until', w.until + 'T23:59:59Z');
  }
  const ledger = await api('/drift?' + params.toString());
  const ids = ledger.scans || [];
  const [first, last] = ids.length >= 2
    ? await Promise.all([ids[0], ids[ids.length - 1]].map((id) => api('/scans/' + encodeURIComponent(id) + '/report')))
    : [null, null];
  const when = (r) => dateTime(r.timestamp);
  const period = first ? `${when(first)} to ${when(last)}` : `${w.since || 'the first scan'} to ${w.until || 'now'}`;

  let h = '<h2>Drift</h2><p class="sub">Which clusters moved against their norm across a window of scans, and the findings that came and went.</p>';
  h += '<div class="controls"><div class="scope-bar" role="group" aria-label="Window"><span class="eyebrow">Last</span>' +
    WINDOWS.map((n) => `<button class="btn${w.scans === n ? ' on' : ''}" data-action="drift-window" data-scans="${n}" aria-pressed="${w.scans === n}">${n} scans</button>`).join('') + '</div>' +
    `<label class="fs-12">From <input type="date" id="driftSince" value="${esc(w.since || '')}"></label>` +
    `<label class="fs-12">To <input type="date" id="driftUntil" value="${esc(w.until || '')}"></label>` +
    '<button class="btn" data-action="drift-range">Apply range</button></div>';
  if (!ids.length) {
    return h + emptyState(w.scans ? 'No scans yet, so there is no window to compare.' : 'No scans fall inside this date range, so pick a wider one.');
  }
  h += renderDriftLedger(ledger, period, { rows: 50 });

  let changed = { added: [], resolved: [] };
  if (first) {
    changed = findingChanges(first.findings || [], last.findings || []);
    h += `<h3>Findings between <a href="${esc(scanHref(ids[0]))}">${esc(ids[0])}</a> and <a href="${esc(scanHref(ids[ids.length - 1]))}">${esc(ids[ids.length - 1])}</a></h3>` +
      '<div class="g g2">' + changeList('New', changed.added, 'crit', 'No new findings.') + changeList('Resolved', changed.resolved, 'ok', 'Nothing resolved.') + '</div>';
  }
  h += `<button class="btn btn-ac mt-12" data-action="copy" data-copy="${esc(driftMarkdown(ledger, period) + changesMarkdown(changed))}">Copy as Markdown</button>`;
  return h;
}

// findingChanges returns the findings in last and not first, and in first and not last, matched
// by fingerprint.
export function findingChanges(first, last) {
  const a = new Map(first.map((f) => [f.fingerprint, f]));
  const b = new Map(last.map((f) => [f.fingerprint, f]));
  return {
    added: last.filter((f) => !a.has(f.fingerprint)),
    resolved: first.filter((f) => !b.has(f.fingerprint)),
  };
}

// changeList renders one column of changed findings.
function changeList(title, list, tone, empty) {
  const rows = list.slice(0, 50).map((f) => `<div class="fs-12 my-8"><span class="tag bg-${esc(f.severity === 'critical' ? 'crit' : f.severity === 'warning' ? 'warn' : 'info')} c-${tone}">${esc(f.severity)}</span> ` +
    `<a href="${esc(clusterHref(f.cluster))}">${esc(f.cluster)}</a> · ${esc(f.title)}</div>`).join('');
  const more = list.length > 50 ? `<p class="note">and ${list.length - 50} more</p>` : '';
  return `<div class="cd"><h3 class="c-${tone} mt-0">${esc(title)} (${list.length})</h3>${rows || `<p class="sub">${esc(empty)}</p>`}${more}</div>`;
}

// changesMarkdown formats the changed findings as Markdown.
function changesMarkdown(c) {
  if (!c.added.length && !c.resolved.length) return '';
  const lines = ['', '', `### New findings (${c.added.length})`];
  c.added.forEach((f) => lines.push(`- ${f.severity} ${f.cluster}: ${f.title}`));
  lines.push('', `### Resolved findings (${c.resolved.length})`);
  c.resolved.forEach((f) => lines.push(`- ${f.severity} ${f.cluster}: ${f.title}`));
  return lines.join('\n');
}

on('drift-window', (btn) => nav('drift', { query: { scans: btn.dataset.scans } }));
on('drift-range', () => {
  const since = document.getElementById('driftSince').value;
  const until = document.getElementById('driftUntil').value;
  nav('drift', { query: { since, until } });
});
