// The dashboard: the score card with its ledger folded away, the globe strip,
// the fields furthest from the norm, the drift ledger for the last week, and
// the worst clusters. Each number shows once.

import { api } from '../api.js';
import { esc, scanHref, clusterHref, byId, emptyState } from '../dom.js';
import { ago, isoSeconds } from '../format.js';
import { renderBar, noteCriticalCount } from '../shell.js';
import { renderScoreCard } from '../components/score-card.js';
import { renderWaterfall, mountWaterfall } from '../components/waterfall.js';
import { renderGlobeStrip, mountGlobeStrip } from '../components/globe-strip.js';
import { renderStrips } from '../components/strip.js';
import { renderDriftLedger } from '../components/drift-ledger.js';
import { renderClusterTable } from '../components/cluster-table.js';
import { openFindingsFiltered } from './findings.js';
import { on } from '../actions.js';
import { triggerScan } from './trigger.js';

// STRIP_FIELDS is how many of the most deviant fields the strip panel shows.
const STRIP_FIELDS = 5;

// DRIFT_DAYS and DRIFT_SCANS bound the drift ledger: the last week, at most
// ten scans of it.
const DRIFT_DAYS = 7;
const DRIFT_SCANS = 10;

let lastReport = null;
let stripScope = 'fleet';

// latestReport returns the report the dashboard last rendered, for the
// command palette's cluster list.
export function latestReport() {
  return lastReport;
}

// renderDash builds the dashboard for the latest scan.
export async function renderDash() {
  renderBar('<button class="btn btn-ok" data-action="trigger-scan">Trigger scan</button>');
  const scans = await api('/scans?limit=2');
  if (!scans || !scans.length) return emptyState('No scans yet, so the dashboard fills in after the first one, which Trigger scan starts.');
  const since = isoSeconds(new Date(Date.now() - DRIFT_DAYS * 864e5));
  const [rpt, prev, forecast, ledger, forecasts, cohorts] = await Promise.all([
    api('/scans/' + encodeURIComponent(scans[0].id) + '/report'),
    scans.length >= 2
      ? api('/scans/' + encodeURIComponent(scans[1].id) + '/report').then((r) => ({ score: r.fleet_score.score, ts: scans[1].timestamp })).catch(() => null)
      : null,
    api('/forecast/fleet-score').then((r) => (r && r.forecast) || null).catch(() => null),
    api(`/drift?scans=${DRIFT_SCANS}&since=${encodeURIComponent(since)}`).catch(() => null),
    api('/forecast/clusters').catch(() => null),
    api('/cohorts').catch(() => ({ cohorts: [] })),
  ]);
  lastReport = rpt;
  noteCriticalCount(scans[0].id, rpt.findings);
  const scopes = ['fleet'].concat(((cohorts && cohorts.cohorts) || []).map((c) => c.name));
  if (!scopes.includes(stripScope)) stripScope = 'fleet';

  let h = `<h2>Fleet overview</h2><p class="sub" data-tip="${esc(rpt.timestamp)}">Latest scan ${esc(ago(rpt.timestamp))}</p>`;
  if (rpt.degraded && rpt.degraded.length) {
    const degClusters = new Set(rpt.degraded.map((d) => d.cluster));
    h += `<div class="banner warn">&#9888; ${rpt.degraded.length} scanner run${rpt.degraded.length === 1 ? '' : 's'} could not read ${degClusters.size} cluster${degClusters.size === 1 ? '' : 's'}. Coverage is partial.</div>`;
  }
  h += '<div class="dash-top">' + renderScoreCard(rpt.fleet_score, rpt.score_attribution, prev, forecast, facts(rpt, scans[0].id)) + renderGlobeStrip() + '</div>';
  if (rpt.score_attribution) {
    h += '<details class="score-ledger" id="scoreLedger"><summary data-action="score-ledger">How the score adds up</summary><div id="scoreLedgerBody"></div></details>';
  }
  h += '<section class="dash-sec"><div class="sec-head"><h3>Furthest from the norm</h3>' +
    `<div class="scope-bar" role="group" aria-label="Norm scope"><span class="eyebrow">Norm</span>${scopeButtons(scopes)}</div></div>` +
    `<div id="dashStrips">${await stripPanel(stripScope)}</div></section>`;
  h += `<section class="dash-sec"><h3>Drift this week</h3>${renderDriftLedger(ledger, 'the last ' + DRIFT_DAYS + ' days', { rows: 5 })}` +
    '<a class="fs-12" href="#/drift">The full drift view &rarr;</a></section>';
  h += `<section class="dash-sec"><h3>Worst clusters</h3>${renderClusterTable(clusterRows(rpt, forecasts))}</section>`;
  return { html: h, post: mountGlobeStrip };
}

// facts returns the scan's counts for the score card. The critical count is
// the Findings badge, so it is not repeated here.
function facts(rpt, scanId) {
  const findings = rpt.findings || [];
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const S = rpt.summary || {};
  return [
    { label: 'findings', value: findings.length, href: '#/findings' },
    { label: 'warnings', value: warnings, action: 'dash-warnings', tip: 'List the warning findings.' },
    { label: 'scanners disagree', value: S.divergent_count || 0, href: scanHref(scanId), tip: 'Scanners whose values differ across the fleet. Opens the scan report.' },
    { label: 'fields diverge', value: S.total_divergences || 0, href: scanHref(scanId), tip: 'Fields with more than one value across the fleet. Opens the scan report.' },
  ];
}

// scopeButtons renders the norm scope toggle.
function scopeButtons(scopes) {
  return scopes.map((s) => `<button class="btn${s === stripScope ? ' on' : ''}" data-action="dash-scope" data-scope="${esc(s)}" aria-pressed="${s === stripScope}">${esc(s)}</button>`).join('');
}

// stripPanel renders the strips of the fields with the most deviation mass
// in a scope.
async function stripPanel(scope) {
  const resp = await api('/distributions?scope=' + encodeURIComponent(scope)).catch(() => ({ distributions: [] }));
  const top = (resp.distributions || []).filter((d) => d.mass > 0).sort((a, b) => b.mass - a.mass).slice(0, STRIP_FIELDS);
  return renderStrips(top, { empty: 'Every cluster sits at the norm in this scope.' }) +
    '<a class="fs-12" href="#/outliers">Every field on the Outliers page &rarr;</a>';
}

// clusterRows joins the report's cluster health, capacity status, score
// cost, and deviation mass with the per-cluster forecasts into table rows. A
// row's status is the worse of its findings status and its capacity status.
function clusterRows(rpt, forecasts) {
  const status = {};
  (rpt.capacity || []).forEach((ca) => { status[ca.cluster] = ca.status; });
  const cost = (rpt.score_attribution && rpt.score_attribution.by_cluster) || {};
  const mass = rpt.deviation_mass || {};
  const projected = {};
  ((forecasts && forecasts.forecasts) || []).forEach((f) => {
    if (f.forecast && f.forecast.sufficient) projected[f.cluster] = f.forecast.predicted - f.current_score;
  });
  const rank = { critical: 0, degraded: 1, busy: 2, healthy: 3 };
  const worse = (a, b) => ((rank[a] ?? 3) <= (rank[b] ?? 3) ? a : b);
  return (rpt.cluster_healths || []).map((ch) => {
    const cap = status[ch.name] === 'strained' ? 'degraded' : status[ch.name];
    const counts = ch.finding_counts || {};
    return {
      cluster: ch.name,
      status: cap ? worse(ch.status, cap) : ch.status,
      cost: cost[ch.name] || 0,
      mass: mass[ch.name] || 0,
      critical: counts.critical || 0,
      warning: counts.warning || 0,
      cpu: ch.avg_cpu,
      memory: ch.avg_memory,
      projected: ch.name in projected ? projected[ch.name] : null,
    };
  });
}

// openTerm opens what sits behind a score term: the findings of a findings
// term, the clusters of a cluster term, the worst node's cluster, or the
// version skew findings.
function openTerm(term) {
  const sev = { 'critical-findings': 'critical', 'warning-findings': 'warning', 'info-findings': 'info' }[term];
  if (sev) {
    openFindingsFiltered('', sev);
    return;
  }
  if (term === 'version-skew') {
    openFindingsFiltered('version/skew');
    return;
  }
  if (term === 'worst-node') {
    const e = ((lastReport && lastReport.score_attribution && lastReport.score_attribution.entries) || []).find((x) => x.term === term && x.cluster);
    if (e) location.hash = clusterHref(e.cluster);
    return;
  }
  if (term === 'critical-clusters' || term === 'degraded-clusters') location.hash = '#/clusters';
}

// mountLedger draws the score waterfall the first time the ledger opens.
function mountLedger() {
  const box = byId('scoreLedgerBody');
  const details = byId('scoreLedger');
  if (!box || !details || !details.open || box.dataset.mounted || !lastReport) return;
  box.dataset.mounted = '1';
  box.innerHTML = renderWaterfall(lastReport.score_attribution);
  mountWaterfall(lastReport.score_attribution, lastReport.fleet_score.score, openTerm);
}

on('score-term', (btn) => openTerm(btn.dataset.term));
on('score-ledger', () => requestAnimationFrame(mountLedger));
on('dash-warnings', () => openFindingsFiltered('', 'warning'));
on('rule-findings', (el) => openFindingsFiltered(el.dataset.rule));
on('trigger-scan', () => triggerScan());
on('dash-scope', async (btn) => {
  stripScope = btn.dataset.scope;
  document.querySelectorAll('[data-action="dash-scope"]').forEach((b) => {
    b.classList.toggle('on', b === btn);
    b.setAttribute('aria-pressed', String(b === btn));
  });
  const box = byId('dashStrips');
  if (box) box.innerHTML = await stripPanel(stripScope);
});
