// Theme selection. The default follows the operating system; the toggle
// cycles system, light, and dark, and the choice is kept in localStorage.

const KEY = 'fleetsweeper-theme';
const ORDER = ['system', 'light', 'dark'];

// current returns the saved theme, or "system".
function current() {
  try {
    const v = localStorage.getItem(KEY);
    return ORDER.includes(v) ? v : 'system';
  } catch (_) {
    return 'system';
  }
}

// applyTheme sets data-theme on the root element for an explicit choice and
// removes it for the system default.
export function applyTheme() {
  const t = current();
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}

// cycleTheme moves to the next theme, saves it, and applies it.
export function cycleTheme() {
  const next = ORDER[(ORDER.indexOf(current()) + 1) % ORDER.length];
  try {
    localStorage.setItem(KEY, next);
  } catch (_) { /* the choice lasts for this page only */ }
  applyTheme();
}

// themeLabel names the active theme for the toggle button.
export function themeLabel() {
  return { system: 'Theme: system', light: 'Theme: light', dark: 'Theme: dark' }[current()];
}
