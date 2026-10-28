// DOM helpers shared by every view. esc is the one escape
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

// emptyState returns a view's empty state: one sentence saying why there is
// nothing to show. more, when given, is trusted markup on a line below it,
// such as the command that fills the view.
export function emptyState(sentence, more) {
  return `<div class="empty" data-empty>${esc(sentence)}${more ? `<div class="empty-more">${more}</div>` : ''}</div>`;
}

// SKELETONS gives each skeleton kind its blocks, each a class sized in
// app.css to stand in for the content that replaces it.
const SKELETONS = {
  dash: ['skel-row', 'skel-panel', 'skel-panel', 'skel-table'],
  cards: ['skel-grid'],
  short: ['skel-panel'],
  stack: ['skel-panel', 'skel-panel'],
  list: ['skel-line', 'skel-line', 'skel-line', 'skel-line', 'skel-line', 'skel-line', 'skel-line', 'skel-line'],
  table: ['skel-bar', 'skel-panel', 'skel-table'],
  chart: ['skel-panel', 'skel-table'],
  map: ['skel-map'],
  detail: ['skel-row', 'skel-panel', 'skel-table'],
};

// skeleton returns the loading placeholder for a kind of view: a heading, a
// subtitle, and blocks sized like the view's content, so first paint does
// not jump when the data arrives.
export function skeleton(kind) {
  const blocks = (SKELETONS[kind] || SKELETONS.list).map((c) => `<div class="skel ${c}"></div>`).join('');
  return `<div class="skeleton" data-loading aria-busy="true" aria-label="Loading"><div class="skel skel-h"></div><div class="skel skel-sub"></div>${blocks}</div>`;
}

// byId returns the element with the given id, or null.
export function byId(id) {
  return document.getElementById(id);
}
