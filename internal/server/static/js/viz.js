// Shared helpers for the SVG and CSS-grid visualizations: scales, stable
// jitter, convex hulls, and the tone of a z-score.

// linear returns a function mapping [d0, d1] onto [r0, r1]. A zero-width
// domain maps everything to the middle of the range.
export function linear(d0, d1, r0, r1) {
  if (d1 === d0) return () => (r0 + r1) / 2;
  return (v) => r0 + ((v - d0) / (d1 - d0)) * (r1 - r0);
}

// hash returns a stable 32-bit hash of s.
export function hash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

// jitter returns a stable offset in [-1, 1] for key, so dots keep their
// place across renders.
export function jitter(key) {
  return (hash(key) % 2001) / 1000 - 1;
}

// zLevel buckets a capped |z| into 0 to 5 for a sequential color scale: 0
// below 1, then 1, 2, 3.5, 6, and 10.
export function zLevel(z) {
  const a = Math.abs(z || 0);
  if (a < 1) return 0;
  if (a < 2) return 1;
  if (a < 3.5) return 2;
  if (a < 6) return 3;
  if (a < 10) return 4;
  return 5;
}

// hull returns the convex hull of points [{x, y}] in counterclockwise order
// (Andrew's monotone chain). Fewer than three points come back as they are.
export function hull(points) {
  const pts = points.slice().sort((a, b) => (a.x - b.x) || (a.y - b.y));
  if (pts.length < 3) return pts;
  const cross = (o, a, b) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower = [];
  for (const p of pts) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop();
    lower.push(p);
  }
  const upper = [];
  for (let i = pts.length - 1; i >= 0; i--) {
    const p = pts[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop();
    upper.push(p);
  }
  upper.pop();
  lower.pop();
  return lower.concat(upper);
}

// fieldLabel names a distribution's field for display.
export function fieldLabel(d) {
  return d.scanner + '/' + d.field;
}

// cohortTones returns a function naming the categorical color class of a
// cohort. Colors go to the sorted distinct names in turn, so up to six
// cohorts never share a color and every view colors a cohort the same way.
export function cohortTones(names) {
  const sorted = [...new Set(names.filter(Boolean))].sort();
  return (name) => {
    const i = sorted.indexOf(name);
    return 'cat-' + ((i < 0 ? hash(name || '') : i) % 6);
  };
}
