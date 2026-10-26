// HTTP access to the fleetsweeper API. Every read goes through api() so an
// interceptor (the demo enrichment) can wrap it in one place.

const interceptors = [];

// intercept registers fn(path, next) around every api() read. fn must call
// next(path) to reach the server, and may change what comes back.
export function intercept(fn) {
  interceptors.push(fn);
}

// fetchJSON performs a GET against /api and returns the decoded body, or
// throws with the status text on a non-2xx response.
async function fetchJSON(path) {
  const r = await fetch('/api' + path, { headers: authHeaders() });
  if (!r.ok) throw new Error(r.statusText || 'HTTP ' + r.status);
  return r.json();
}

// api reads path under /api through the registered interceptors.
export function api(path) {
  const chain = interceptors.reduceRight((next, fn) => (p) => fn(p, next), fetchJSON);
  return chain(path);
}

// authHeaders returns the Authorization header for the token saved in this
// browser, or none.
export function authHeaders() {
  let token = '';
  try {
    token = sessionStorage.getItem('fleetsweeper-token') || '';
  } catch (_) {
    token = '';
  }
  return token ? { Authorization: 'Bearer ' + token } : {};
}

// apiSend sends a JSON body with method to path under /api and returns the
// raw Response so callers can branch on status.
export function apiSend(method, path, body) {
  return fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

let catalog = null;

// loadScannerCatalog fetches the scanner list once, keyed by id. A failure
// leaves the catalog empty so labels fall back to ids.
export async function loadScannerCatalog() {
  if (catalog) return catalog;
  catalog = {};
  try {
    (await api('/scanners')).forEach((s) => { catalog[s.id] = s; });
  } catch (_) {
    catalog = {};
  }
  return catalog;
}

// scannerLabel returns the human-readable name of a scanner, or its id.
export function scannerLabel(id) {
  return (catalog && catalog[id] && catalog[id].label) || id;
}
