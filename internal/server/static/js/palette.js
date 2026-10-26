// The Cmd-K command palette: pages from the route table, scan triggering, and
// the clusters of the last dashboard report.

import { ROUTES } from './routes.js';
import { nav } from './router.js';
import { esc } from './dom.js';
import { latestReport } from './views/dash.js';
import { triggerScan } from './views/trigger.js';
import { openModal } from './components/modal.js';

let overlay = null;

// items returns every palette entry.
function items() {
  const pages = ROUTES.filter((r) => r.group).map((r) => ({ label: r.label, run: () => nav(r.id) }));
  pages.push({ label: 'Trigger scan', run: triggerScan });
  const rpt = latestReport();
  return pages.concat(((rpt && rpt.clusters) || []).map((c) => ({ label: 'Cluster: ' + c, run: () => nav('detail', { cluster: c }) })));
}

// closePalette closes the palette.
function closePalette() {
  if (overlay) overlay.close();
}

// openPalette shows the palette with focus in its search box.
function openPalette() {
  if (overlay) return;
  overlay = openModal({
    className: 'overlay',
    label: 'Command palette',
    html: '<div class="overlay-card"><input type="search" class="cmdk-input" placeholder="Type to search clusters, pages..." aria-label="Search">' +
      '<div class="cmdk-list" role="listbox"></div><div class="overlay-foot">Up/Down to navigate &nbsp;|&nbsp; Enter to select &nbsp;|&nbsp; Esc to close</div></div>',
    onClose: () => { overlay = null; },
  });
  const input = overlay.querySelector('input');
  const list = overlay.querySelector('.cmdk-list');
  let sel = 0;
  let matches = [];
  const draw = () => {
    const q = input.value.toLowerCase();
    matches = items().filter((it) => !q || it.label.toLowerCase().includes(q));
    sel = Math.max(0, Math.min(sel, matches.length - 1));
    list.innerHTML = matches.length
      ? matches.map((it, i) => `<button class="cmdk-item${i === sel ? ' sel' : ''}" role="option" aria-selected="${i === sel}" data-i="${i}">${esc(it.label)}</button>`).join('')
      : '<div class="empty">No matches</div>';
  };
  const choose = (i) => {
    const it = matches[i];
    closePalette();
    if (it) it.run();
  };
  overlay.addEventListener('click', (e) => {
    const item = e.target.closest('.cmdk-item');
    if (item) choose(Number(item.dataset.i));
  });
  input.addEventListener('input', () => {
    sel = 0;
    draw();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' && matches.length) sel = (sel + 1) % matches.length;
    else if (e.key === 'ArrowUp' && matches.length) sel = (sel - 1 + matches.length) % matches.length;
    else if (e.key === 'Enter') choose(sel);
    else if (e.key === 'Escape') closePalette();
    else return;
    e.preventDefault();
    if (overlay) draw();
  });
  draw();
  input.focus();
}

document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    openPalette();
  }
});
