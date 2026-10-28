// HTTP access to the fleetsweeper API.

// errorText returns the server's error message from a failed response.
export async function errorText(r) {
  try {
    const body = await r.clone().json();
    if (body && body.error) return body.error;
  } catch (_) { /* not JSON */ }
  return r.statusText || 'HTTP ' + r.status;
}

// fetchJSON performs a GET against /api and returns the decoded body, or
// throws with the server's error message on a non-2xx response. The error
// carries the HTTP status in its status field.
async function fetchJSON(path) {
  const r = await fetch('/api' + path, { headers: authHeaders() });
  if (!r.ok) {
    const err = new Error(await errorText(r));
    err.status = r.status;
    throw err;
  }
  return r.json();
}

// api reads path under /api.
export function api(path) {
  return fetchJSON(path);
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
