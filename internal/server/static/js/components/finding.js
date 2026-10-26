// The finding card, used for scan findings and inbound alerts alike: a
// severity rail, the title, a meta line (rule, cluster, scanner, how often it
// recurs), the description and affected objects, the remediation folded away
// with a Copy for the whole command, and ack or unack through a drawer.

import { esc, clusterHref, sevTone } from '../dom.js';
import { tip, legacyRemediation } from '../glossary.js';
import { scannerLabel } from '../api.js';
import { on } from '../actions.js';
import { send } from '../auth.js';
import { openDrawer } from './drawer.js';
import { toast } from './toast.js';
import { openWhatIf } from './whatif.js';

// PERSISTENCE_TIPS explains each persistence class.
const PERSISTENCE_TIPS = {
  chronic: 'Present in most recent scans. A standing problem.',
  intermittent: 'Comes and goes across recent scans.',
  transient: 'Seen in few recent scans.',
};

// SNOOZES lists the snooze choices of the ack drawer in hours, zero for a
// permanent ack.
const SNOOZES = [[0, 'Until I remove it'], [24, 'For a day'], [168, 'For a week'], [720, 'For 30 days']];

// remediationFor returns the commands for a finding: the server-supplied one,
// else the legacy lookup, else null.
export function remediationFor(f) {
  if (f.remediation && f.remediation.command) return [f.remediation.command];
  return legacyRemediation(f);
}

// copyBlock renders a remediation block with a Copy button for all of it.
function copyBlock(text) {
  return `<div class="remediation-wrap"><button class="btn copy-btn float" data-action="copy" data-copy="${esc(text)}">Copy</button>` +
    `<div class="remediation">${esc(text)}</div></div>`;
}

// metaLine renders the rule, cluster, scanner, persistence, and time of f.
function metaLine(f, persistence) {
  const parts = [];
  if (f.rule) parts.push(`<span class="mono" data-tip="Rule">${esc(f.rule)}</span>`);
  parts.push(f.cluster && f.cluster !== 'fleet'
    ? `<a href="${esc(clusterHref(f.cluster))}">${esc(f.cluster)}</a>`
    : '<span data-tip="Affects the entire fleet, not a single cluster">fleet</span>');
  parts.push(`<span${tip(f.scanner) ? ` data-tip="${esc(tip(f.scanner))}"` : ''}>${esc(f.kind === 'alert' ? f.scanner : scannerLabel(f.scanner))}</span>`);
  const p = persistence && persistence[f.fingerprint];
  if (p) parts.push(`<span class="c-${p === 'chronic' ? 'crit' : p === 'intermittent' ? 'warn' : 't3'}" data-tip="${esc(PERSISTENCE_TIPS[p] || '')}">${esc(p)}</span>`);
  if (f.when) parts.push(`<span>${esc(f.when)}</span>`);
  return `<div class="fi-meta">${parts.join('<span class="c-t3" aria-hidden="true">&middot;</span>')}</div>`;
}

// normAttrs returns the data attributes a what-if needs for a finding the norm raised: the
// field and the scope of the norm. Absolute-rule findings carry none.
function normAttrs(f) {
  if (!f.norm || !f.affected || !f.affected.length) return '';
  return ` data-field="${esc(f.affected[0])}" data-scope="${esc(f.norm.scope || '')}"`;
}

// whatIfControl renders the What if button for a finding the norm raised.
function whatIfControl(f) {
  if (!f.norm || !f.affected || !f.affected.length || f.cluster === 'fleet') return '';
  return '<button class="btn btn-sm" data-action="whatif" data-tip="Project the fleet with this value fixed to the norm. Nothing is changed.">What if</button>';
}

// ackControl renders the ack state and the button that changes it.
function ackControl(f) {
  if (!f.fingerprint) return '';
  return f.acked
    ? '<span class="pill bg-ok c-ok">acked</span><button class="btn btn-sm finding-ack-btn" data-action="ack" data-tip="Remove the acknowledgement so it fires notifications again">Unack</button>'
    : '<button class="btn btn-sm finding-ack-btn" data-action="ack" data-tip="Acknowledge: the finding dims and stops firing notifications">Ack</button>';
}

// renderFinding returns the markup of one finding card. opts.persistence
// maps a fingerprint to its persistence class. The second argument may be an
// array index when used with map, which is ignored.
export function renderFinding(f, opts) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const tone = sevTone(f.severity);
  const text = [f.title, f.description, f.cluster, f.scanner, f.rule].join(' ').toLowerCase();
  let h = `<article class="fi ${esc(f.severity)}${f.acked ? ' acked' : ''}" data-sev="${esc(f.severity)}" data-cluster="${esc(f.cluster)}"` +
    ` data-scanner="${esc(f.scanner)}" data-title="${esc(f.title)}" data-fp="${esc(f.fingerprint || '')}" data-kind="${esc(f.kind || 'finding')}"` +
    ` data-acked="${f.acked ? '1' : ''}" data-text="${esc(text)}"${normAttrs(f)}>`;
  h += `<div class="fi-head"><span class="tag bg-${tone} c-${tone}" data-tip="${esc(tip('sev_' + f.severity))}">${esc(f.severity)}</span>` +
    `<span class="fi-title">${esc(f.title)}</span>${whatIfControl(f)}<span class="fi-ack">${ackControl(f)}</span></div>`;
  h += metaLine(f, o.persistence);
  if (f.description) h += `<div class="fi-desc">${esc(f.description)}</div>`;
  if (f.affected && f.affected.length) {
    h += '<div class="fi-affected"><span class="eyebrow">Affected:</span> ' +
      f.affected.slice(0, 8).map((a) => `<code>${esc(a)}</code>`).join(' ');
    if (f.affected.length > 8) h += ` <span class="c-t3">+${f.affected.length - 8} more</span>`;
    h += '</div>';
  }
  const rem = remediationFor(f);
  if (rem && rem.length && f.severity !== 'info') {
    const n = rem.join('\n').split('\n').filter((l) => l.trim()).length;
    h += `<details class="fi-fold"><summary>Remediation, ${n} command${n === 1 ? '' : 's'}</summary>${copyBlock(rem.join('\n'))}`;
    if (f.remediation && f.remediation.yaml) h += `<details class="fi-fold"><summary>Baseline YAML</summary>${copyBlock(f.remediation.yaml)}</details>`;
    h += '</details>';
  }
  if (f.labels && Object.keys(f.labels).length) {
    h += '<details class="fi-fold"><summary>Labels</summary><dl class="kv">' +
      Object.keys(f.labels).sort().map((k) => `<dt>${esc(k)}</dt><dd class="mono">${esc(f.labels[k])}</dd>`).join('') + '</dl></details>';
  }
  return h + '</article>';
}

// setAcked updates every card of fingerprint fp in place.
function setAcked(fp, acked) {
  document.querySelectorAll('.fi[data-fp]').forEach((el) => {
    if (el.dataset.fp !== fp) return;
    el.classList.toggle('acked', acked);
    el.dataset.acked = acked ? '1' : '';
    const ack = el.querySelector('.fi-ack');
    if (ack) ack.innerHTML = ackControl({ fingerprint: fp, acked });
  });
}

// snoozeUntil returns the RFC 3339 time hours from now, or undefined for zero.
function snoozeUntil(hours) {
  return hours > 0 ? new Date(Date.now() + hours * 3600e3).toISOString().replace(/\.\d+Z$/, 'Z') : undefined;
}

// openAckDrawer asks for a reason and snooze and acknowledges the card el, or
// confirms and removes its acknowledgement.
function openAckDrawer(el) {
  const fp = el.dataset.fp;
  const isAlert = el.dataset.kind === 'alert';
  const what = `<p class="fs-14 fw-600 mb-4">${esc(el.dataset.title)}</p><p class="note mb-12">${esc(el.dataset.cluster || 'fleet')} &middot; ${esc(el.dataset.scanner)}</p>`;
  if (el.dataset.acked) {
    openDrawer({
      title: 'Remove the acknowledgement',
      body: what + '<p class="note">It will show at full strength again and fire notifications on the next scan.</p>',
      actions: [{
        label: 'Unack',
        tone: 'danger',
        run: async () => {
          if (!await send('DELETE', '/findings/' + encodeURIComponent(fp) + '/ack', undefined, 'Unack')) return false;
          setAcked(fp, false);
          toast('Acknowledgement removed.', 'ok');
          return true;
        },
      }],
    });
    return;
  }
  openDrawer({
    title: isAlert ? 'Acknowledge alert' : 'Acknowledge finding',
    body: what +
      '<label class="field"><span>Reason</span><textarea id="ackReason" rows="3" placeholder="Optional, e.g. a ticket or why it is expected"></textarea></label>' +
      '<label class="field"><span>Snooze</span><select id="ackSnooze">' + SNOOZES.map(([h, l]) => `<option value="${h}">${esc(l)}</option>`).join('') + '</select></label>',
    actions: [{
      label: 'Acknowledge',
      tone: 'primary',
      run: async (panel) => {
        const body = {
          reason: panel.querySelector('#ackReason').value.trim(),
          ack_by: 'dashboard',
          snooze_until: snoozeUntil(Number(panel.querySelector('#ackSnooze').value)),
        };
        const path = isAlert ? '/alerts/' + encodeURIComponent(fp) + '/ack' : '/findings/' + encodeURIComponent(fp) + '/ack';
        if (!isAlert) Object.assign(body, { cluster: el.dataset.cluster || '', scanner: el.dataset.scanner || '', title: el.dataset.title || '' });
        if (!await send('POST', path, body, 'Acknowledge')) return false;
        setAcked(fp, true);
        toast('Acknowledged.', 'ok');
        return true;
      },
    }],
  });
}

on('ack', (btn, ev) => {
  ev.preventDefault();
  const el = btn.closest('.fi');
  if (el && el.dataset.fp) openAckDrawer(el);
});

on('whatif', (btn, ev) => {
  ev.preventDefault();
  const el = btn.closest('.fi');
  if (el && el.dataset.field) openWhatIf(el);
});
