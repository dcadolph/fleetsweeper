// DOM and formatting helpers shared by every view. esc is the one escape
// function: every piece of server data interpolated into markup goes through
// it, or is set with textContent.

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

// esc returns s with & < > " ' replaced by entities, safe in text and in
// quoted attribute values. null and undefined become the empty string.
export function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

// clusterHref returns the hash link to a cluster's detail page.
export function clusterHref(name) {
  return '#/cluster/' + encodeURIComponent(name);
}

// scanHref returns the hash link to a stored scan's report page.
export function scanHref(id) {
  return '#/scan/' + encodeURIComponent(id);
}

// clusterLink returns an anchor to a cluster's detail page with extra
// classes.
export function clusterLink(name, cls) {
  return `<a href="${esc(clusterHref(name))}"${cls ? ` class="${cls}"` : ''}>${esc(name)}</a>`;
}

// pct formats a percentage, or N/A for a missing or negative value.
export function pct(n) {
  return n == null || n < 0 ? 'N/A' : Math.round(n) + '%';
}

// fmtUSD formats a number with thousands separators and two decimals.
export function fmtUSD(n) {
  if (typeof n !== 'number' || Number.isNaN(n)) return '0.00';
  const parts = Math.abs(n).toFixed(2).split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (n < 0 ? '-' : '') + parts.join('.');
}

// humanAgo formats an ISO-8601 timestamp as "Ns ago", "Nm ago", "Nh ago", or
// "Nd ago", or returns it unchanged when it does not parse.
export function humanAgo(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const hr = Math.round(m / 60);
  if (hr < 48) return hr + 'h ago';
  return Math.round(hr / 24) + 'd ago';
}

// sevTone maps a finding severity to a status tone.
export function sevTone(sev) {
  return sev === 'critical' ? 'crit' : sev === 'warning' ? 'warn' : 'info';
}

// statusTone maps a cluster or capacity status to a status tone.
export function statusTone(status) {
  switch (status) {
    case 'critical': return 'crit';
    case 'degraded': case 'strained': return 'warn';
    case 'busy': return 'info';
    case 'healthy': return 'ok';
    default: return 'muted';
  }
}

// threshTone maps a utilization percentage to a tone: ok below 70, warn up
// to 85, crit above.
export function threshTone(v) {
  return v > 85 ? 'crit' : v > 70 ? 'warn' : 'ok';
}

// token reads a CSS custom property from the root element, so canvas drawing
// follows the active theme.
export function token(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// toneColor returns the theme color of a tone.
export function toneColor(tone) {
  return token(tone === 'muted' ? '--text-3' : '--status-' + tone);
}

// csvExport downloads rows as a CSV file with a header row.
export function csvExport(filename, headers, rows) {
  let csv = headers.join(',') + '\n';
  rows.forEach((r) => {
    csv += r.map((c) => '"' + String(c == null ? '' : c).replace(/"/g, '""') + '"').join(',') + '\n';
  });
  download(filename, csv, 'text/csv');
}

// download saves text as a file.
export function download(filename, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// copyText writes text to the clipboard, falling back to a hidden textarea
// where the Clipboard API is not available, such as plain-http origins.
export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.className = 'sr-only';
  document.body.appendChild(ta);
  ta.select();
  try {
    if (!document.execCommand('copy')) throw new Error('copy refused');
  } finally {
    document.body.removeChild(ta);
  }
}

// byId returns the element with the given id, or null.
export function byId(id) {
  return document.getElementById(id);
}
