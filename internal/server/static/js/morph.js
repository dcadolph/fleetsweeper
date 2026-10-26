// morph patches an element's children toward new markup instead of
// replacing them, so a refresh keeps what the viewer did to the page: form
// controls keep their values, open details stay open, focus and scroll stay
// where they were. Nodes are matched by position, tag, and id.

// sameNode reports whether have can be patched into want rather than
// replaced.
function sameNode(have, want) {
  if (have.nodeType !== want.nodeType || have.nodeName !== want.nodeName) return false;
  return have.nodeType !== Node.ELEMENT_NODE || (have.id || '') === (want.id || '');
}

// isControl reports whether el holds viewer input.
function isControl(el) {
  return el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement;
}

// patchAttributes makes have's attributes match want's, except the ones that
// carry viewer state: value and checked on controls, open on details.
function patchAttributes(have, want) {
  const keep = (name) => (isControl(have) && (name === 'value' || name === 'checked')) || (have.nodeName === 'DETAILS' && name === 'open');
  [...have.attributes].forEach((a) => {
    if (!want.hasAttribute(a.name) && !keep(a.name)) have.removeAttribute(a.name);
  });
  [...want.attributes].forEach((a) => {
    if (keep(a.name)) return;
    if (have.getAttribute(a.name) !== a.value) have.setAttribute(a.name, a.value);
  });
}

// patchChildren patches from's child list toward to's.
function patchChildren(from, to) {
  const have = [...from.childNodes];
  const want = [...to.childNodes];
  want.forEach((w, i) => {
    const h = have[i];
    if (!h) from.appendChild(w);
    else if (!sameNode(h, w)) from.replaceChild(w, h);
    else patchNode(h, w);
  });
  for (let i = want.length; i < have.length; i++) have[i].remove();
}

// patchNode patches one matched node.
function patchNode(have, want) {
  if (have.nodeType === Node.TEXT_NODE || have.nodeType === Node.COMMENT_NODE) {
    if (have.nodeValue !== want.nodeValue) have.nodeValue = want.nodeValue;
    return;
  }
  if (have.nodeType !== Node.ELEMENT_NODE) return;
  patchAttributes(have, want);
  if (have.nodeName === 'CANVAS' || isControl(have) && have.nodeName !== 'SELECT') return;
  if (have.nodeName === 'SELECT') {
    const value = have.value;
    patchChildren(have, want);
    if ([...have.options].some((o) => o.value === value)) have.value = value;
    return;
  }
  patchChildren(have, want);
}

// morph patches target's children toward html.
export function morph(target, html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = html;
  patchChildren(target, tpl.content);
}
