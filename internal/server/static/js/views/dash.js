// The dashboard: fleet score, summary tiles with drilldowns, cluster health
// cards, utilization charts, top findings, and the forecast, cost, and
// integration panels.

import { api, scannerLabel } from '../api.js';
import { esc, pct, fmtUSD, humanAgo, clusterHref, sevTone, statusTone, threshTone, byId } from '../dom.js';
import { TIPS, tip } from '../glossary.js';
import { renderBar } from '../shell.js';
import { renderFinding } from '../components/finding.js';
import { miniGauge, utilizationBars } from '../charts.js';
import { on } from '../actions.js';
import { triggerScan } from './trigger.js';

let lastReport = null;

// latestReport returns the report the dashboard last rendered, for the
// command palette's cluster list.
export function latestReport() {
  return lastReport;
}

// renderDash builds the dashboard for the latest scan, with the score delta
// against the previous scan when there is one.
export async function renderDash() {
  renderBar('<button class="btn btn-ok" data-action="trigger-scan">Trigger scan</button>');
  const scans = await api('/scans?limit=2');
  if (!scans || !scans.length) return '<div class="empty">No scans yet. Run a scan first.</div>';
  const rpt = await api('/scans/' + encodeURIComponent(scans[0].id) + '/report');
  let prevScore = null;
  let prevTs = null;
  if (scans.length >= 2) {
    try {
      const prev = await api('/scans/' + encodeURIComponent(scans[1].id) + '/report');
      if (prev && prev.fleet_score && typeof prev.fleet_score.score === 'number') {
        prevScore = prev.fleet_score.score;
        prevTs = scans[1].timestamp;
      }
    } catch (_) { /* the delta is optional */ }
  }
  let forecast = null;
  try {
    const fr = await api('/forecast/fleet-score');
    if (fr && fr.forecast) forecast = fr.forecast;
  } catch (_) { /* the forecast is optional */ }

  lastReport = rpt;
  const S = rpt.summary;
  let h = `<h2>Fleet overview</h2><p class="sub">Latest scan: ${esc(rpt.timestamp)} &middot; ${S.cluster_count} clusters &middot; ${rpt.findings ? rpt.findings.length : 0} findings</p>`;
  h += '<nav class="dash-toc" aria-label="Dashboard sections">' +
    [['dash-score', 'Score'], ['dash-summary', 'Summary'], ['dash-health', 'Cluster health'], ['dash-util', 'Utilization'], ['dash-findings', 'Findings'], ['dash-cost', 'Cost']]
      .map(([id, label]) => `<button class="toc-link" data-action="jump" data-jump="${id}">${label}</button>`).join('') +
    '</nav>';

  if (rpt.degraded && rpt.degraded.length) {
    const degClusters = new Set(rpt.degraded.map((d) => d.cluster));
    h += `<div class="banner warn">&#9888; ${rpt.degraded.length} scanner run(s) degraded across ${degClusters.size} cluster(s). Coverage is partial; some data may be missing.</div>`;
  }

  h += `<div id="dash-score">${fleetScoreHero(rpt.fleet_score, prevScore, prevTs, forecast)}</div>`;
  if (rpt.brief && rpt.brief.headline) {
    h += '<div class="panel"><div class="eyebrow mb-4">Scan summary</div>' +
      `<div class="fs-14 fw-600 mb-4">${esc(rpt.brief.headline)}</div>` +
      (rpt.brief.lines || []).map((l) => `<div class="fs-12 c-t2">&bull; ${esc(l)}</div>`).join('') +
      '</div>';
  }

  h += '<div class="g g6" data-tour="summary" id="dash-summary">';
  h += summaryTile('ac', S.cluster_count, 'Clusters', TIPS.clusters + ' Click to view all clusters.', 'nav-clusters', '');
  h += summaryTile('ok', S.uniform_count, 'Uniform', TIPS.uniform + ' Click to view.', 'drill', 'uniform');
  h += summaryTile('crit', S.divergent_count, 'Divergent', TIPS.divergent + ' Click to view.', 'drill', 'divergent');
  h += summaryTile('crit', S.critical_count, 'Critical', TIPS.critical + ' Click to view.', 'drill', 'critical');
  h += summaryTile('warn', S.warning_count, 'Warnings', TIPS.warnings + ' Click to view.', 'drill', 'warning');
  h += summaryTile('t2', S.total_divergences, 'Issues', TIPS.issues + ' Click to view divergent scanners.', 'drill', 'divergent');
  h += '</div><div id="dashDrilldown"></div>';

  if (rpt.cluster_healths && rpt.cluster_healths.length) h += healthCards(rpt);

  h += '<h3 id="dash-util">Resource utilization</h3><div class="g g2">' +
    '<div class="chc"><h4>CPU utilization by cluster</h4><div class="chart-200"><canvas id="dashCpu"></canvas></div></div>' +
    '<div class="chc"><h4>Memory utilization by cluster</h4><div class="chart-200"><canvas id="dashMem"></canvas></div></div>' +
    '</div>';

  if (rpt.findings && rpt.findings.length) {
    const crit = rpt.findings.filter((f) => f.severity === 'critical');
    const warn = rpt.findings.filter((f) => f.severity === 'warning');
    h += `<h3 id="dash-findings">Top findings <a href="#/findings" class="fs-12 fw-500">(view all ${rpt.findings.length})</a></h3>`;
    if (crit.length) h += `<div class="fs-12 fw-600 c-crit mb-4">Critical (${crit.length})</div>` + crit.slice(0, 5).map(renderFinding).join('');
    if (warn.length) h += `<div class="fs-12 fw-600 c-warn my-8">Warning (${warn.length})</div>` + warn.slice(0, 5).map(renderFinding).join('');
  }
  h += '<div id="dashForecastPanel"></div><div id="dashCostPanel"></div><div id="dashIntegrationsPanel"></div>';

  return {
    html: h,
    post() {
      if (rpt.cluster_healths) {
        rpt.cluster_healths.forEach((ch) => {
          const safe = canvasId(ch.name);
          miniGauge('gc-' + safe, ch.avg_cpu, 'CPU');
          miniGauge('gm-' + safe, ch.avg_memory, 'Mem');
        });
        const labels = rpt.cluster_healths.map((c) => c.name);
        utilizationBars('dashCpu', labels, rpt.cluster_healths.map((c) => c.avg_cpu));
        utilizationBars('dashMem', labels, rpt.cluster_healths.map((c) => c.avg_memory));
      }
      loadForecastPanel();
      loadCostPanel();
      loadIntegrationsPanel();
    },
  };
}

// canvasId turns a cluster name into a safe element id fragment.
function canvasId(name) {
  return name.replace(/[^a-z0-9]/gi, '_');
}

// summaryTile renders one clickable summary tile.
function summaryTile(tone, value, label, tipText, action, arg) {
  return `<button class="cd st click" data-action="${action}" data-drill="${esc(arg)}" data-tip="${esc(tipText)}">` +
    `<span class="v c-${tone}">${value}</span><span class="l">${label}</span></button>`;
}

// healthCards renders the cluster health cards grouped by correlated status,
// worst group first and open.
function healthCards(rpt) {
  const capMap = {};
  (rpt.capacity || []).forEach((ca) => { capMap[ca.cluster] = ca; });
  const rank = { critical: 0, degraded: 1, busy: 2, healthy: 3 };
  const statusOf = (ch) => {
    const st = capMap[ch.name] ? capMap[ch.name].status : ch.status;
    return st === 'strained' ? 'degraded' : st;
  };
  const groups = {};
  rpt.cluster_healths.slice().sort((a, b) => (rank[statusOf(a)] ?? 3) - (rank[statusOf(b)] ?? 3)).forEach((ch) => {
    (groups[statusOf(ch)] = groups[statusOf(ch)] || []).push(ch);
  });
  const labels = { critical: 'Critical', degraded: 'Degraded', busy: 'Busy', healthy: 'Healthy' };
  let h = '<h3 data-tour="health-cards" id="dash-health">Cluster health</h3>';
  ['critical', 'degraded', 'busy', 'healthy'].forEach((st) => {
    const group = groups[st];
    if (!group || !group.length) return;
    const tone = statusTone(st);
    h += `<details class="chgroup"${st === 'critical' || st === 'degraded' ? ' open' : ''}><summary>` +
      `<span class="dot fill-${tone}"></span><span class="fs-12 fw-600 c-${tone}">${labels[st]}</span>` +
      `<span class="fs-12 c-t3">(${group.length} clusters)</span></summary><div class="g g3">`;
    group.forEach((ch) => {
      const ca = capMap[ch.name] || {};
      const cardTone = statusTone(ca.status || st);
      h += `<div class="cd cc" data-href="${esc(clusterHref(ch.name))}" role="link" tabindex="0" data-tip="Click to view full cluster detail">` +
        `<div class="ind fill-${cardTone}"></div><h4>${esc(ch.name)}</h4>` +
        `<div class="row"><span>Version</span><span class="val">${esc(ch.kubernetes_version || 'N/A')}</span></div>` +
        `<div class="row"><span>Nodes</span><span class="val">${ch.healthy_nodes}/${ch.node_count}</span></div>` +
        `<div class="row"><span>CPU</span><span class="val c-${threshTone(ch.avg_cpu)}">${pct(ch.avg_cpu)}</span></div>` +
        `<div class="row"><span>Memory</span><span class="val c-${threshTone(ch.avg_memory)}">${pct(ch.avg_memory)}</span></div>`;
      if (ca.recommendation) {
        const r = ca.recommendation;
        h += `<div class="rec">${esc(r.length > 120 ? r.substring(0, 120) + '...' : r)}</div>`;
      }
      h += `<div class="gauges"><canvas id="gc-${canvasId(ch.name)}" width="70" height="40"></canvas><canvas id="gm-${canvasId(ch.name)}" width="70" height="40"></canvas></div></div>`;
    });
    h += '</div></details>';
  });
  return h;
}

// fleetScoreHero renders the score card: gauge, delta against the previous
// scan, headline, provenance, drivers, and the forecast.
function fleetScoreHero(fs, prevScore, prevTs, forecast) {
  if (!fs || typeof fs.score !== 'number') return '';
  const gradeTone = { A: 'ok', B: 'ok', C: 'warn', D: 'crit', F: 'crit' }[fs.grade] || 't2';
  const scoreTone = fs.score >= 80 ? 'ok' : fs.score >= 60 ? 'warn' : 'crit';

  let delta = '';
  if (prevScore != null) {
    const d = fs.score - prevScore;
    const arrow = d > 0 ? '&#9650;' : d < 0 ? '&#9660;' : '&#8211;';
    const tone = d > 0 ? 'ok' : d < 0 ? 'crit' : 't2';
    delta = `<div class="fs-12 c-${tone} mt-4" data-tip="Compared to the previous scan${prevTs ? ' at ' + esc(prevTs) : ''}">` +
      `${arrow} ${d > 0 ? '+' : ''}${d} pts${prevTs ? ' since ' + esc(humanAgo(prevTs)) : ''}</div>`;
  }

  let prov = '';
  if (typeof fs.sample_size === 'number' && fs.sample_size > 0) {
    let text = `Scored from ${fs.sample_size} cluster${fs.sample_size === 1 ? '' : 's'} across ${fs.dimensions || 0} dimension${fs.dimensions === 1 ? '' : 's'}.`;
    if (fs.excluded_clusters > 0) {
      text += ` ${fs.excluded_clusters} cluster${fs.excluded_clusters === 1 ? '' : 's'} excluded for insufficient data.`;
    }
    prov = `<div class="fs-12 c-t2 mt-4" data-tip="A score is only as strong as its sample. Clusters with no usable scanner data are excluded.">${esc(text)}</div>`;
  }

  const drivers = fs.drivers && fs.drivers.length
    ? '<div class="chips">' + fs.drivers.map((d) => `<span class="chip" data-tip="Pulled the score down by ${d.impact} points">${esc(d.reason)} &middot; -${d.impact}</span>`).join('') + '</div>'
    : '';

  let fc = '';
  if (forecast && forecast.sufficient && typeof forecast.predicted === 'number') {
    const pd = forecast.predicted - fs.score;
    const tone = pd > 0 ? 'ok' : pd < 0 ? 'crit' : 't2';
    const band = Math.max(0, forecast.upper - forecast.lower);
    fc = `<div class="forecast" data-tip="Linear regression forecast from the last ${forecast.basis} scans. R² = ${(forecast.r_squared || 0).toFixed(2)}. Slope = ${(forecast.slope_per_hour || 0).toFixed(3)} pts/hr.">` +
      '<span class="eyebrow">Projected next scan</span>' +
      `<span class="fs-18 fw-700 c-${tone}">${forecast.predicted}${band > 0 ? ' ± ' + Math.round(band / 2) : ''}</span>` +
      `<span class="fs-12 c-${tone}">(${pd > 0 ? '+' : ''}${pd} pts)</span>` +
      `<span class="fs-12 c-t2 ml-auto">${esc(forecast.headline || '')}</span></div>`;
  }

  const r = 42;
  const circ = 2 * Math.PI * r;
  const arc = Math.max(0, Math.min(100, fs.score)) / 100 * circ;
  const gauge = '<svg class="score-gauge" width="118" height="118" viewBox="0 0 120 120" role="img" aria-label="Fleet score ' + fs.score + ' of 100">' +
    `<circle class="track" cx="60" cy="60" r="${r}" fill="none" stroke-width="9"/>` +
    `<circle cx="60" cy="60" r="${r}" fill="none" stroke="var(--status-${scoreTone})" stroke-width="9" stroke-linecap="round" stroke-dasharray="${arc.toFixed(1)} ${(circ - arc).toFixed(1)}" transform="rotate(-90 60 60)"/>` +
    `<text class="num" x="60" y="60" text-anchor="middle">${fs.score}</text>` +
    `<text class="grade" x="60" y="80" text-anchor="middle" fill="var(--${gradeTone === 't2' ? 'text-2' : 'status-' + gradeTone})">${esc(fs.grade)}</text></svg>`;

  return '<div class="cd pad-lg" data-tour="fleet-score"><div class="score-hero">' +
    `<div class="center">${gauge}<div class="eyebrow mt-4" data-tip="Single 0-100 fleet health score. Lower is worse. Computed from finding severities, cluster health distribution, version skew, and worst-cluster node health.">Fleet score</div>${delta}</div>` +
    `<div class="score-side"><div class="fs-14 lh-tight">${esc(fs.headline || '')}</div>${prov}${drivers}</div>` +
    `</div>${fc}</div>`;
}

// loadForecastPanel fills the per-cluster forecast table with clusters
// projected to worsen, best effort.
function loadForecastPanel() {
  const el = byId('dashForecastPanel');
  if (!el) return;
  api('/forecast/clusters').then((d) => {
    if (!d || !d.forecasts || !d.forecasts.length) return;
    const rows = d.forecasts.filter((f) => f.forecast && f.forecast.sufficient).filter((r) => {
      const delta = r.forecast.predicted - r.current_score;
      return delta < 0 || (r.current_score < 80 && Math.abs(delta) < 3);
    }).slice(0, 6);
    if (!rows.length) return;
    let h = `<h3>Most likely to degrade <span class="fs-12 fw-500 c-t3">(linear projection, last ${rows[0].forecast.basis || '?'} scans)</span></h3>`;
    h += '<div class="tw"><table><thead><tr><th>Cluster</th><th>Now</th><th>Projected</th><th>Delta</th><th>R²</th><th>Headline</th></tr></thead><tbody>';
    rows.forEach((r) => {
      const delta = r.forecast.predicted - r.current_score;
      const tone = delta < 0 ? 'crit' : delta > 0 ? 'ok' : 't2';
      h += `<tr class="click" data-href="${esc(clusterHref(r.cluster))}"><td class="fw-500"><a href="${esc(clusterHref(r.cluster))}">${esc(r.cluster)}</a></td>` +
        `<td class="mono">${r.current_score}</td><td class="mono">${r.forecast.predicted} ± ${Math.round((r.forecast.upper - r.forecast.lower) / 2)}</td>` +
        `<td class="mono c-${tone}">${delta > 0 ? '+' : ''}${delta}</td><td class="mono">${(r.forecast.r_squared || 0).toFixed(2)}</td>` +
        `<td class="fs-12 c-t2">${esc(r.forecast.headline || '')}</td></tr>`;
    });
    el.innerHTML = h + '</tbody></table></div>';
  }).catch(() => {});
}

// costStat renders one labeled figure in the cost summary.
function costStat(label, val, tone, size) {
  return `<div><div class="eyebrow">${esc(label)}</div><div class="${size} fw-700 c-${tone}">${val}</div></div>`;
}

// loadCostPanel fills the cost-correlation panel when a cost CSV is loaded.
function loadCostPanel() {
  const el = byId('dashCostPanel');
  if (!el) return;
  api('/cost').then((d) => {
    if (!d || d.total_fleet_usd <= 0) return;
    const share = Math.round(100 * d.total_drift_usd / d.total_fleet_usd);
    const tone = share >= 15 ? 'crit' : share >= 5 ? 'warn' : 'ok';
    const priced = d.by_cluster ? d.by_cluster.length : 0;
    const missing = d.missing_cost ? d.missing_cost.length : 0;
    let h = `<h3 id="dash-cost">Cost correlation <span class="fs-12 fw-500 c-t3">(billing period ${esc(d.period || 'n/a')})</span></h3>`;
    h += '<p class="fs-12 c-t2 mb-12">Drift cost estimates the monthly spend attributable to divergence. Per cluster it is ' +
      '<span class="mono c-t1">cost &times; (100 &minus; health score) / 100</span>. A cluster at score 100 attributes nothing; one at score 60 attributes 40% of its bill. The fleet figure sums every priced cluster.</p>';
    h += '<div class="cd mb-12"><div class="cost-stats">' +
      costStat('Drift cost / mo', '$' + fmtUSD(d.total_drift_usd), tone, 'fs-28') +
      costStat('Fleet spend / mo', '$' + fmtUSD(d.total_fleet_usd), 't1', 'fs-18') +
      costStat('Share drifting', share + '%', tone, 'fs-18') +
      costStat('Clusters priced', priced + (missing ? ' of ' + (priced + missing) : ''), 't2', 'fs-18') +
      '</div>' +
      `<div class="share-bar" data-tip="Drift is ${share}% of fleet spend"><div class="fill-${tone}" style="width:${share}%"></div></div>` +
      `<div class="flex between fs-12 c-t3 mt-4"><span>drift $${fmtUSD(d.total_drift_usd)}</span><span>healthy $${fmtUSD(Math.max(0, d.total_fleet_usd - d.total_drift_usd))}</span></div></div>`;
    if (d.by_cluster && d.by_cluster.length) {
      h += '<div class="tw"><table><thead><tr><th>Cluster</th>' +
        '<th data-tip="Monthly cost from the billing CSV">Cost / mo</th>' +
        '<th data-tip="Cluster health score, 0 to 100">Score</th>' +
        '<th data-tip="100 minus the score: the unhealthy fraction of spend">Health gap</th>' +
        '<th data-tip="Cost times health gap: spend attributed to drift">Drift cost</th>' +
        '<th data-tip="This cluster as a share of total drift cost">% of drift</th></tr></thead><tbody>';
      d.by_cluster.slice(0, 12).forEach((c) => {
        const ct = c.score < 60 ? 'crit' : c.score < 80 ? 'warn' : 'ok';
        const of = d.total_drift_usd > 0 ? Math.round(100 * c.drift_usd / d.total_drift_usd) : 0;
        h += `<tr class="click" data-href="${esc(clusterHref(c.cluster))}"><td class="fw-500"><a href="${esc(clusterHref(c.cluster))}">${esc(c.cluster)}</a></td>` +
          `<td class="mono">$${fmtUSD(c.cost_usd)}</td><td class="mono c-${ct}">${c.score}</td><td class="mono c-${ct}">${100 - c.score}%</td>` +
          `<td class="mono ${c.drift_usd > 0 ? 'c-crit' : 'c-t2'}">$${fmtUSD(c.drift_usd)}</td><td class="mono">${of}%</td></tr>`;
      });
      h += '</tbody></table></div>';
      if (d.by_cluster.length > 12) h += `<div class="note mt-4">Showing the top 12 of ${d.by_cluster.length} clusters by drift cost.</div>`;
    }
    if (missing) {
      h += `<div class="note mt-8">No billing row for ${missing} cluster(s): ${d.missing_cost.slice(0, 6).map(esc).join(', ')}${missing > 6 ? ' (+' + (missing - 6) + ' more)' : ''}. They are excluded from the totals.</div>`;
    }
    el.innerHTML = h;
  }).catch(() => {});
}

// loadIntegrationsPanel fills the integrations grid.
function loadIntegrationsPanel() {
  const el = byId('dashIntegrationsPanel');
  if (!el) return;
  api('/integrations').then((d) => {
    if (!d || !d.items) return;
    let h = '<h3>Integrations <span class="fs-12 fw-500 c-t3">(configured vs available)</span></h3><div class="g g3">';
    d.items.forEach((it) => {
      const isOn = it.status === 'configured' || it.status === 'demo';
      h += `<div class="cd${isOn ? ' bg-ok' : ''}"><div class="flex between items-center">` +
        `<div class="fs-12 fw-500">${esc(it.name)}</div><span class="fs-12 fw-600 ${isOn ? 'c-ok' : 'c-t3'}">${esc(it.status)}</span></div>` +
        (it.hint ? `<div class="note mt-4">${esc(it.hint)}</div>` : '') + '</div>';
    });
    el.innerHTML = h + '</div>';
  }).catch(() => {});
}

// showDrilldown fills the drilldown under the summary tiles.
function showDrilldown(type) {
  const rpt = lastReport;
  const el = byId('dashDrilldown');
  if (!rpt || !el) return;
  const close = '<button class="btn btn-sm" data-action="clear" data-target="dashDrilldown">Close</button>';
  let h = '<div class="cd mb-12"><div class="flex between items-center mb-8"><h4>';
  if (type === 'uniform' || type === 'divergent') {
    const isDiv = type === 'divergent';
    h += (isDiv ? 'Divergent' : 'Uniform') + ' scanners</h4>' + close + '</div>';
    h += '<table><thead><tr><th>Scanner</th><th>Status</th><th data-tip="Click a count to see per-cluster values">Divergences</th></tr></thead><tbody>';
    Object.keys(rpt.sections || {}).sort().forEach((k) => {
      const sec = rpt.sections[k];
      if (isDiv === !!sec.uniform) return;
      const n = sec.divergences ? sec.divergences.length : 0;
      h += `<tr><td class="fw-500"${tip(k) ? ` data-tip="${esc(tip(k))}"` : ''}>${esc(scannerLabel(k))}</td>` +
        `<td class="${sec.uniform ? 'c-ok' : 'c-crit'}" data-tip="${esc(isDiv ? TIPS.divergent : TIPS.uniform)}">${sec.uniform ? 'Uniform' : 'Divergent'}</td>`;
      h += n > 0
        ? `<td class="mono"><button class="btn btn-ac" data-action="scanner-divergences" data-scanner="${esc(k)}" data-tip="Click to see per-cluster values for each divergent field">${n} details</button></td>`
        : '<td class="mono c-t3">0</td>';
      h += '</tr>';
    });
    h += '</tbody></table><div id="scannerDivDetail"></div>';
  } else {
    h += type.charAt(0).toUpperCase() + type.slice(1) + ' findings</h4>' + close + '</div>';
    const filtered = (rpt.findings || []).filter((f) => f.severity === type);
    h += filtered.length ? filtered.map(renderFinding).join('') : '<div class="fs-12 c-t2 my-8">None found.</div>';
    h += '<div class="mt-8"><a href="#/findings" class="fs-12">View all findings &rarr;</a></div>';
  }
  el.innerHTML = h + '</div>';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// showScannerDivergences fills the per-field, per-cluster divergence table of
// one scanner.
function showScannerDivergences(key) {
  const rpt = lastReport;
  const sec = rpt && rpt.sections && rpt.sections[key];
  const el = byId('scannerDivDetail');
  if (!sec || !sec.divergences || !el) return;
  const clusters = rpt.clusters || [];
  let h = '<div class="panel inset mt-12"><div class="flex between items-center mb-8">' +
    `<h4>${esc(scannerLabel(key))} divergences</h4><button class="btn btn-sm" data-action="clear" data-target="scannerDivDetail">Close</button></div>`;
  h += `<div class="tw"><table><thead><tr><th data-tip="${esc(TIPS.sev_critical)}">Severity</th><th>Field</th>` +
    clusters.map((c) => `<th><a href="${esc(clusterHref(c))}">${esc(c)}</a></th>`).join('') + '</tr></thead><tbody>';
  sec.divergences.forEach((d) => {
    const tone = sevTone(d.severity);
    const first = d.values && d.values[clusters[0]] ? d.values[clusters[0]] : '';
    h += `<tr><td data-tip="${esc(tip('sev_' + d.severity))}"><span class="flex items-center gap-4"><span class="dot fill-${tone}"></span><span class="fs-12">${esc(d.severity)}</span></span></td>` +
      `<td class="fw-500"${tip(d.field) ? ` data-tip="${esc(tip(d.field))}"` : ''}>${esc(d.field)}</td>`;
    clusters.forEach((c) => {
      const val = d.values && d.values[c] ? d.values[c] : '-';
      const diff = val !== first && val !== '-';
      h += `<td class="mono${diff ? ' c-crit fw-600' : ''}">${esc(val)}</td>`;
    });
    h += '</tr>';
  });
  el.innerHTML = h + '</tbody></table></div></div>';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

on('drill', (el) => showDrilldown(el.dataset.drill));
on('nav-clusters', () => { location.hash = '#/clusters'; });
on('scanner-divergences', (el) => showScannerDivergences(el.dataset.scanner));
on('trigger-scan', () => triggerScan());
on('jump', (el) => {
  const target = byId(el.dataset.jump);
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (target) target.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
});
