// Delegated event handling. Markup names an action with data-action (click)
// or data-change (input and change), and a module registers
// the handler by name. One listener per event type serves the whole page, so
// no element carries an inline handler and re-rendered markup needs no
// rewiring.

const handlers = { click: new Map(), change: new Map() };

// on registers fn(el, event) for elements with data-action="name".
export function on(name, fn) {
  handlers.click.set(name, fn);
}

// onChange registers fn(el, event) for inputs with data-change="name", run
// on both input and change events.
export function onChange(name, fn) {
  handlers.change.set(name, fn);
}

// dispatch runs the handler named by attr on the closest element carrying it.
function dispatch(kind, attr, ev) {
  const el = ev.target.closest('[' + attr + ']');
  if (!el) return;
  const fn = handlers[kind].get(el.getAttribute(attr));
  if (!fn) return;
  fn(el, ev);
}

// installActions attaches the document-level listeners once.
export function installActions() {
  document.addEventListener('click', (ev) => {
    const href = ev.target.closest('[data-href]');
    if (href && !ev.target.closest('a, button, input, select, [data-action]')) {
      location.hash = href.getAttribute('data-href');
      return;
    }
    dispatch('click', 'data-action', ev);
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    const href = ev.target.closest('[data-href]');
    if (href && ev.target === href) {
      ev.preventDefault();
      location.hash = href.getAttribute('data-href');
    }
  });
  document.addEventListener('input', (ev) => dispatch('change', 'data-change', ev));
  document.addEventListener('change', (ev) => {
    if (ev.target.matches('input[type=search], input[type=text]')) return;
    dispatch('change', 'data-change', ev);
  });
}
