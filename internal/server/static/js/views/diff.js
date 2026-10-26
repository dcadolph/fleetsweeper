// The scan diff page: findings new and resolved between two scans.

import { api } from '../api.js';
import { esc } from '../dom.js';
import { renderBar } from '../shell.js';
import { P, render } from '../router.js';
import { on } from '../actions.js';

// renderDiff compares the scans chosen in P.diffA and P.diffB, defaulting to
// the latest two.
export async function renderDiff() {
  renderBar('');
  const scans = await api('/scans?limit=20');
  if (!scans || scans.length < 2) return '<div class="empty">Need at least 2 scans for diff. Trigger a scan from the Dashboard.</div>';
  const aId = P.diffA || scans[1].id;
  const bId = P.diffB || scans[0].id;
  const opts = (sel) => scans.map((s) => `<option value="${esc(s.id)}"${s.id === sel ? ' selected' : ''}>${esc(s.id)} · ${esc(s.timestamp)}</option>`).join('');
  let h = '<h2>Scan diff</h2><p class="sub">Compare two scans to see what changed: findings that resolved, findings that are new, summary deltas.</p>';
  h += '<div class="controls fs-12">' +
    `<label>Base (older): <select id="diffA">${opts(aId)}</select></label>` +
    `<label>Target (newer): <select id="diffB">${opts(bId)}</select></label>` +
    '<button class="btn btn-ac" data-action="diff-compare">Compare</button></div>';
  const [ra, rb] = await Promise.all([api('/scans/' + encodeURIComponent(aId) + '/report'), api('/scans/' + encodeURIComponent(bId) + '/report')]);
  const key = (f) => f.fingerprint || [f.severity, f.cluster, f.scanner, f.title].join('|');
  const aSet = new Map((ra.findings || []).map((f) => [key(f), f]));
  const bSet = new Map((rb.findings || []).map((f) => [key(f), f]));
  const resolved = [...aSet].filter(([k]) => !bSet.has(k)).map(([, f]) => f);
  const added = [...bSet].filter(([k]) => !aSet.has(k)).map(([, f]) => f);
  const row = (f, tone) => `<div class="fs-12 my-8"><span class="tag bg-${tone} c-${tone}">${esc(f.severity)}</span> ${esc(f.cluster)} · ${esc(f.title)}</div>`;
  h += '<div class="g g2">' +
    `<div class="cd"><h3 class="c-crit mt-0">New (${added.length})</h3>${added.length ? added.slice(0, 50).map((f) => row(f, 'crit')).join('') : '<p class="sub">No new findings.</p>'}</div>` +
    `<div class="cd"><h3 class="c-ok mt-0">Resolved (${resolved.length})</h3>${resolved.length ? resolved.slice(0, 50).map((f) => row(f, 'ok')).join('') : '<p class="sub">No resolved findings.</p>'}</div></div>`;
  h += `<button class="btn btn-ac mt-12" data-action="copy" data-copy="${esc(diffMarkdown(aId, bId, resolved, added))}">Copy Markdown summary</button>`;
  return h;
}

// diffMarkdown formats a scan diff as Markdown for pasting into a channel.
function diffMarkdown(a, b, resolved, added) {
  const lines = ['## Scan diff: ' + a + ' → ' + b, '', '### Resolved (' + resolved.length + ')'];
  resolved.forEach((f) => lines.push('- ' + f.severity + ' ' + f.cluster + ': ' + f.title));
  lines.push('', '### New (' + added.length + ')');
  added.forEach((f) => lines.push('- ' + f.severity + ' ' + f.cluster + ': ' + f.title));
  return lines.join('\n');
}

on('diff-compare', () => {
  P.diffA = document.getElementById('diffA').value;
  P.diffB = document.getElementById('diffB').value;
  render();
});
