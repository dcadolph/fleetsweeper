// The finding card used on every page that lists findings, and its ack
// action.

import { esc, clusterHref, sevTone } from '../dom.js';
import { tip, legacyRemediation } from '../glossary.js';
import { apiSend, scannerLabel } from '../api.js';
import { on } from '../actions.js';

// remediationFor returns the commands for a finding: the server-supplied one,
// else the legacy lookup, else null.
export function remediationFor(f) {
  if (f.remediation && f.remediation.command) return [f.remediation.command];
  return legacyRemediation(f);
}

// copyBlock renders a remediation block with a Copy button.
function copyBlock(text, tipText) {
  return `<div class="remediation-wrap"><button class="btn copy-btn float" data-action="copy" data-copy="${esc(text)}">Copy</button>` +
    `<div class="remediation"${tipText ? ` data-tip="${esc(tipText)}"` : ''}>${esc(text)}</div></div>`;
}

// renderFinding returns the markup of one finding card.
export function renderFinding(f) {
  const tone = sevTone(f.severity);
  const text = [f.title, f.description, f.cluster, f.scanner].join(' ').toLowerCase();
  let h = `<div class="fi ${esc(f.severity)}${f.acked ? ' acked' : ''}" data-sev="${esc(f.severity)}" data-cluster="${esc(f.cluster)}"` +
    ` data-scanner="${esc(f.scanner)}" data-title="${esc(f.title)}" data-fp="${esc(f.fingerprint || '')}" data-text="${esc(text)}">`;
  h += '<div class="fi-head">';
  h += `<span class="tag bg-${tone} c-${tone}" data-tip="${esc(tip('sev_' + f.severity))}">${esc(f.severity)}</span>`;
  h += `<span class="tag bg-muted c-t3" data-tip="${esc(tip(f.scanner))}">${esc(scannerLabel(f.scanner))}</span>`;
  if (f.cluster && f.cluster !== 'fleet') {
    h += `<a class="tag bg-info c-info" href="${esc(clusterHref(f.cluster))}" data-tip="View cluster detail">${esc(f.cluster)}</a>`;
  } else {
    h += '<span class="tag bg-muted c-t2" data-tip="Affects the entire fleet, not a single cluster">fleet</span>';
  }
  h += `<button class="tag bg-muted ${f.acked ? 'c-ok' : 'c-t3'} ml-auto finding-ack-btn" data-action="ack"` +
    ' data-tip="Acknowledge this finding; it will dim and stop firing Slack notifications">' + (f.acked ? 'acked' : 'ack') + '</button>';
  h += '</div>';
  h += `<div class="fi-title">${esc(f.title)}</div>`;
  h += `<div class="fi-desc">${esc(f.description)}</div>`;
  if (f.affected && f.affected.length) {
    h += '<div class="fi-affected"><span class="eyebrow">Affected:</span> ' +
      f.affected.slice(0, 8).map((a) => `<code>${esc(a)}</code>`).join(' ');
    if (f.affected.length > 8) h += ` <span class="c-t3">+${f.affected.length - 8} more</span>`;
    h += '</div>';
  }
  const rem = remediationFor(f);
  if (rem && rem.length && f.severity !== 'info') {
    h += copyBlock(rem.join('\n'), 'Suggested kubectl commands. Use the Copy button or triple-click to select.');
    if (f.remediation && f.remediation.yaml) {
      h += `<details class="yaml-details"><summary>Baseline YAML</summary>${copyBlock(f.remediation.yaml)}</details>`;
    }
  }
  h += '</div>';
  return h;
}

// ackFinding acknowledges the finding card el on the server, then dims it in
// place.
async function ackFinding(el) {
  const fp = el.dataset.fp || '';
  if (!fp) return;
  const reason = prompt('Reason (optional):', '') || '';
  try {
    const resp = await apiSend('POST', '/findings/' + encodeURIComponent(fp) + '/ack', {
      cluster: el.dataset.cluster || '',
      scanner: el.dataset.scanner || '',
      title: el.dataset.title || '',
      reason,
    });
    if (resp.ok) {
      el.classList.add('acked');
      const btn = el.querySelector('.finding-ack-btn');
      if (btn) {
        btn.textContent = 'acked';
        btn.classList.replace('c-t3', 'c-ok');
      }
    } else if (resp.status === 401 || resp.status === 403) {
      alert('The server requires a token to acknowledge findings.');
    } else {
      alert('Ack failed: ' + resp.status);
    }
  } catch (e) {
    alert('Ack error: ' + e.message);
  }
}

on('ack', (btn, ev) => {
  ev.preventDefault();
  ackFinding(btn.closest('.fi'));
});
