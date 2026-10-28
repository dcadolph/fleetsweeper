// Number and date formatting. Every number or date a view writes into the
// page goes through this module, so a value reads the same everywhere it
// appears. Views and components never call toFixed or toLocaleString
// themselves; a static test enforces it.

// num formats a number with at most two decimals, and thousands separators
// from 1000 up. A value that is not a finite number comes back as a string.
export function num(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return String(n);
  return Math.abs(n) >= 1000 ? Math.round(n).toLocaleString() : String(Math.round(n * 100) / 100);
}

// fixed formats a number with exactly digits decimals, or the empty string
// for a value that is not a finite number.
export function fixed(n, digits) {
  return typeof n === 'number' && Number.isFinite(n) ? n.toFixed(digits) : '';
}

// coord formats an SVG coordinate or length with one decimal.
export function coord(n) {
  return (Number.isFinite(n) ? n : 0).toFixed(1);
}

// pct formats a percentage as a whole number, or N/A for a missing or
// negative value.
export function pct(n) {
  return n == null || n < 0 ? 'N/A' : Math.round(n) + '%';
}

// usd formats an amount with thousands separators and two decimals, without
// a currency sign.
export function usd(n) {
  if (typeof n !== 'number' || Number.isNaN(n)) return '0.00';
  const parts = Math.abs(n).toFixed(2).split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (n < 0 ? '-' : '') + parts.join('.');
}

// ago formats an ISO-8601 timestamp as "Ns ago", "Nm ago", "Nh ago", or
// "Nd ago", or returns it unchanged when it does not parse.
export function ago(iso) {
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

// parsed returns iso as a Date, or null when it does not parse.
function parsed(iso) {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t);
}

// dateTime formats a timestamp as a local date and time, as in "Oct 26,
// 9:14 PM", or the empty string when it does not parse.
export function dateTime(iso) {
  const d = parsed(iso);
  return d ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '';
}

// day formats a timestamp as a local month and day, as in "Oct 26", or the
// empty string when it does not parse.
export function day(iso) {
  const d = parsed(iso);
  return d ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '';
}

// date formats a timestamp as a local date with the year, as in "Oct 26,
// 2026", or the empty string when it does not parse.
export function date(iso) {
  const d = parsed(iso);
  return d ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '';
}

// isoSeconds formats a Date as UTC ISO-8601 without fractional seconds, the
// form the API takes in query parameters.
export function isoSeconds(d) {
  return d.toISOString().replace(/\.\d+Z$/, 'Z');
}

// isoDay formats a Date as its UTC calendar day, YYYY-MM-DD.
export function isoDay(d) {
  return d.toISOString().slice(0, 10);
}
