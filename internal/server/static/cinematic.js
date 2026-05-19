// Fleetsweeper cinematic explainer. Tells the fleet-is-the-policy story
// across ten scenes, ~95 seconds total. ES5 only, no frameworks, no
// build step. SVG primitives via document.createElementNS. One accent
// color (signal blue). Respects prefers-reduced-motion. Pauses on
// document.hidden.

(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var STAGE_W = 1100;
  var STAGE_H = 560;
  var ACCENT = '#58a6ff';
  var OK = '#3fb950';
  var WN = '#d29922';
  var CR = '#f85149';
  var PU = '#a371f7';
  var BD = '#30363d';
  var MU = '#8b949e';
  var HD = '#f0f6fc';
  var TX = '#c9d1d9';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------- SVG helpers ----------
  function el(tag, attrs, parent) {
    var node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k)) {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    if (parent) parent.appendChild(node);
    return node;
  }

  function txt(parent, x, y, content, opts) {
    opts = opts || {};
    var t = el('text', {
      x: x, y: y,
      fill: opts.fill || TX,
      'font-family': opts.mono ? '"SF Mono","JetBrains Mono",monospace' : '-apple-system,Segoe UI,Roboto,sans-serif',
      'font-size': opts.size || 14,
      'font-weight': opts.weight || 400,
      'text-anchor': opts.anchor || 'start',
      'dominant-baseline': opts.baseline || 'auto'
    }, parent);
    t.textContent = content;
    if (opts.opacity != null) t.setAttribute('opacity', opts.opacity);
    return t;
  }

  function clearStage() {
    var stage = document.getElementById('fs-cin-stage');
    while (stage.firstChild) stage.removeChild(stage.firstChild);
    return makeStageSVG(stage);
  }

  function makeStageSVG(parent) {
    return el('svg', {
      viewBox: '0 0 ' + STAGE_W + ' ' + STAGE_H,
      preserveAspectRatio: 'xMidYMid meet'
    }, parent);
  }

  // ---------- Scene engine ----------
  var scenes = [];
  var idx = 0;
  var playing = true;
  var sceneStart = 0;
  var teardown = null;
  var ticker = null;

  function totalDuration() {
    var t = 0;
    for (var i = 0; i < scenes.length; i++) t += scenes[i].duration;
    return t;
  }

  function elapsedBefore(i) {
    var t = 0;
    for (var j = 0; j < i; j++) t += scenes[j].duration;
    return t;
  }

  function paintCaption(sc) {
    var cap = document.getElementById('fs-cin-caption');
    cap.innerHTML = '<div class="hl">' + sc.headline + '</div>' +
      '<div class="sb">' + (sc.subcaption || '') + '</div>';
  }

  function paintProgress() {
    document.getElementById('fs-cin-progress').textContent =
      'scene ' + (idx + 1) + ' / ' + scenes.length;
  }

  function startScene(i) {
    if (teardown) { try { teardown(); } catch (_) {} teardown = null; }
    idx = Math.max(0, Math.min(i, scenes.length - 1));
    var sc = scenes[idx];
    sceneStart = Date.now();
    paintCaption(sc);
    paintProgress();
    var svg = clearStage();
    try {
      teardown = sc.paint(svg) || null;
    } catch (e) {
      // Fail closed: log to caption so the cinematic stays readable.
      var cap = document.getElementById('fs-cin-caption');
      cap.innerHTML = '<div class="hl">Scene error</div><div class="sb">' + e.message + '</div>';
    }
    if (reduceMotion) {
      // No animation; just advance after a beat.
      window.clearTimeout(ticker);
      ticker = window.setTimeout(advance, Math.min(sc.duration, 2000));
    }
  }

  function advance() {
    if (idx >= scenes.length - 1) {
      startScene(0);
      return;
    }
    startScene(idx + 1);
  }

  function tick() {
    if (!playing || reduceMotion) return paintScrubber();
    var sc = scenes[idx];
    if (!sc) return;
    var elapsed = Date.now() - sceneStart;
    if (elapsed >= sc.duration) {
      advance();
    }
    paintScrubber();
  }

  function paintScrubber() {
    var total = totalDuration();
    if (total <= 0) return;
    var sc = scenes[idx];
    var done = elapsedBefore(idx) + Math.min(Date.now() - sceneStart, sc.duration);
    var pct = Math.min(100, (done / total) * 100);
    var fill = document.getElementById('fs-cin-fill');
    var head = document.getElementById('fs-cin-head');
    fill.style.width = pct + '%';
    head.style.left = pct + '%';
  }

  // ---------- Scrubber: markers, hover, drag ----------
  function paintMarkers() {
    var bar = document.getElementById('fs-cin-scrubber');
    var total = totalDuration();
    var t = 0;
    for (var i = 0; i < scenes.length - 1; i++) {
      t += scenes[i].duration;
      var m = document.createElement('div');
      m.className = 'fs-cin-marker';
      m.style.left = ((t / total) * 100) + '%';
      bar.appendChild(m);
    }
  }

  function wireScrubber() {
    var bar = document.getElementById('fs-cin-scrubber');
    var tip = document.getElementById('fs-cin-tooltip');
    var dragging = false;

    function pctFromEvent(e) {
      var rect = bar.getBoundingClientRect();
      var x = (e.touches ? e.touches[0].clientX : e.clientX) - rect.left;
      return Math.max(0, Math.min(1, x / rect.width));
    }

    function sceneAt(pct) {
      var total = totalDuration();
      var t = pct * total;
      var acc = 0;
      for (var i = 0; i < scenes.length; i++) {
        if (t < acc + scenes[i].duration) return i;
        acc += scenes[i].duration;
      }
      return scenes.length - 1;
    }

    bar.addEventListener('mousemove', function (e) {
      var pct = pctFromEvent(e);
      var i = sceneAt(pct);
      var rect = bar.getBoundingClientRect();
      var x = (e.clientX - rect.left);
      tip.style.left = x + 'px';
      tip.style.opacity = '1';
      tip.textContent = scenes[i].label;
      if (dragging) seekTo(pct);
    });
    bar.addEventListener('mouseleave', function () { tip.style.opacity = '0'; });
    bar.addEventListener('mousedown', function (e) {
      dragging = true;
      seekTo(pctFromEvent(e));
    });
    window.addEventListener('mouseup', function () { dragging = false; });
  }

  function seekTo(pct) {
    var total = totalDuration();
    var t = pct * total;
    var acc = 0;
    for (var i = 0; i < scenes.length; i++) {
      if (t < acc + scenes[i].duration) {
        startScene(i);
        sceneStart = Date.now() - (t - acc);
        return;
      }
      acc += scenes[i].duration;
    }
    startScene(scenes.length - 1);
  }

  // ---------- Controls ----------
  function wireControls() {
    document.getElementById('fs-cin-prev').addEventListener('click', function () {
      startScene(idx - 1);
    });
    document.getElementById('fs-cin-next').addEventListener('click', function () {
      startScene(idx + 1);
    });
    document.getElementById('fs-cin-restart').addEventListener('click', function () {
      startScene(0);
    });
    var pauseBtn = document.getElementById('fs-cin-pause');
    pauseBtn.addEventListener('click', function () {
      playing = !playing;
      pauseBtn.textContent = playing ? 'Pause' : 'Play';
      if (playing) sceneStart = Date.now() - (sceneStart ? 0 : 0);
    });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        playing = false;
        pauseBtn.textContent = 'Play';
      }
    });
  }

  // ---------- Reusable primitives ----------
  function cluster(svg, x, y, r, state, label) {
    var g = el('g', {transform: 'translate(' + x + ',' + y + ')'}, svg);
    var color = state === 'ok' ? OK : (state === 'warn' ? WN : (state === 'crit' ? CR : ACCENT));
    el('circle', {r: r, fill: 'none', stroke: color, 'stroke-width': 1.5, opacity: 0.6}, g);
    el('circle', {r: r * 0.45, fill: color, opacity: 0.9}, g);
    if (label) txt(g, 0, r + 18, label, {fill: MU, size: 11, anchor: 'middle', mono: true});
    return g;
  }

  function pulse(svg, x, y, r, color, delay) {
    if (reduceMotion) return null;
    var c = el('circle', {cx: x, cy: y, r: r, fill: 'none', stroke: color, 'stroke-width': 2, opacity: 0.9}, svg);
    var anim = el('animate', {
      attributeName: 'r', from: r, to: r + 35, dur: '1.2s',
      begin: (delay || 0) + 's', repeatCount: 'indefinite'
    }, c);
    el('animate', {
      attributeName: 'opacity', from: 0.9, to: 0,
      dur: '1.2s', begin: (delay || 0) + 's', repeatCount: 'indefinite'
    }, c);
    return c;
  }

  function bar(svg, x, y, w, h, frac, color) {
    el('rect', {x: x, y: y, width: w, height: h, fill: '#21262d', rx: 3}, svg);
    el('rect', {x: x, y: y, width: w * frac, height: h, fill: color, rx: 3}, svg);
  }

  // ---------- Scenes ----------
  scenes.push({
    label: 'Hello',
    duration: 6500,
    headline: 'Twelve clusters. One fleet.',
    subcaption: 'Each one drifts independently. <span class="accent">Fleetsweeper</span> spots when one moves away from the rest.',
    paint: function (svg) {
      txt(svg, STAGE_W / 2, 60, 'fleetsweeper', {
        fill: ACCENT, size: 32, weight: 700, anchor: 'middle', mono: true
      });
      txt(svg, STAGE_W / 2, 92, 'the fleet is the policy', {
        fill: MU, size: 14, anchor: 'middle'
      });
      var positions = [
        [220, 280], [330, 220], [450, 260], [560, 200], [680, 250], [800, 230],
        [240, 380], [360, 420], [480, 380], [600, 430], [720, 380], [850, 410]
      ];
      var labels = ['prod-east', 'prod-west', 'staging', 'dev-1', 'dev-2', 'edge-nyc',
                    'edge-sfo', 'edge-lon', 'qa-1', 'qa-2', 'eu-prod', 'apac'];
      var clusters = [];
      for (var i = 0; i < positions.length; i++) {
        clusters.push(cluster(svg, positions[i][0], positions[i][1], 18, 'idle', labels[i]));
      }
      // pulse a couple
      pulse(svg, positions[3][0], positions[3][1], 18, ACCENT, 0);
      pulse(svg, positions[8][0], positions[8][1], 18, ACCENT, 0.6);
      return null;
    }
  });

  scenes.push({
    label: 'Drift',
    duration: 7500,
    headline: 'No two clusters ever stay identical.',
    subcaption: 'Versions drift. Manifests drift. Add-ons drift. The fleet itself is the only ground truth.',
    paint: function (svg) {
      var rows = [
        {label: 'kube-apiserver', vals: ['1.29.4', '1.29.4', '1.28.7', '1.29.4', '1.30.0', '1.29.4']},
        {label: 'cilium', vals: ['1.15.2', '1.15.2', '1.15.2', '1.14.9', '1.15.2', '1.15.2']},
        {label: 'cert-manager', vals: ['1.13.0', '1.13.0', '1.13.0', '1.13.0', '1.13.0', '1.13.0']},
        {label: 'admission policies', vals: ['28', '28', '21', '28', '34', '28']}
      ];
      var clusters = ['prod-east', 'prod-west', 'staging', 'dev-1', 'eu-prod', 'apac'];
      var startX = 220, startY = 130;
      var colW = 100, rowH = 70;
      for (var c = 0; c < clusters.length; c++) {
        txt(svg, startX + colW * c + colW / 2, startY, clusters[c], {
          fill: MU, size: 11, anchor: 'middle', mono: true
        });
      }
      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        txt(svg, startX - 30, startY + 40 + rowH * r + 10, row.label, {
          fill: TX, size: 13, anchor: 'end'
        });
        // mode value
        var modeVal = mode(row.vals);
        for (var c2 = 0; c2 < row.vals.length; c2++) {
          var isOutlier = row.vals[c2] !== modeVal;
          var bg = isOutlier ? CR : OK;
          el('rect', {
            x: startX + colW * c2 + 6,
            y: startY + 22 + rowH * r,
            width: colW - 12, height: 32,
            fill: 'none', stroke: bg, 'stroke-width': isOutlier ? 2 : 1,
            opacity: isOutlier ? 1 : 0.4, rx: 5
          }, svg);
          txt(svg,
            startX + colW * c2 + colW / 2,
            startY + 42 + rowH * r,
            row.vals[c2],
            {fill: isOutlier ? CR : TX, size: 12, anchor: 'middle', mono: true});
        }
      }
      txt(svg, STAGE_W / 2, STAGE_H - 36,
        'no rules. just the fleet voting on what is normal.',
        {fill: ACCENT, size: 13, anchor: 'middle'});
    }
  });

  scenes.push({
    label: 'Outliers',
    duration: 8500,
    headline: 'Statistical outliers, not hand-written rules.',
    subcaption: 'Modified <span class="accent">z-score</span> against the fleet median surfaces the clusters that wandered off.',
    paint: function (svg) {
      // Axis
      var ax = 120, ay = 360, aw = 860;
      el('line', {x1: ax, y1: ay, x2: ax + aw, y2: ay, stroke: BD, 'stroke-width': 1}, svg);
      txt(svg, ax, ay + 22, 'cluster z-score across the fleet', {fill: MU, size: 11});
      // dots
      var dots = [
        {x: 0.20, z: 0.1, name: 'prod-east'},
        {x: 0.27, z: -0.2, name: 'prod-west'},
        {x: 0.34, z: 0.3, name: 'staging'},
        {x: 0.40, z: -0.1, name: 'dev-1'},
        {x: 0.46, z: 0.4, name: 'dev-2'},
        {x: 0.52, z: 0.0, name: 'edge-nyc'},
        {x: 0.58, z: -0.3, name: 'edge-sfo'},
        {x: 0.64, z: 0.2, name: 'edge-lon'},
        {x: 0.71, z: 0.1, name: 'qa-1'},
        {x: 0.78, z: 0.0, name: 'qa-2'},
        {x: 0.85, z: 0.2, name: 'eu-prod'},
        {x: 0.92, z: 3.6, name: 'apac', outlier: true}
      ];
      // band: -1 to 1 z range
      el('rect', {x: ax, y: ay - 60, width: aw, height: 60, fill: ACCENT, opacity: 0.06}, svg);
      txt(svg, ax + 8, ay - 64, 'fleet norm band (|z| < 1)',
        {fill: ACCENT, size: 10, opacity: 0.85});
      for (var i = 0; i < dots.length; i++) {
        var d = dots[i];
        var cx = ax + d.x * aw;
        var cy = ay - Math.min(180, d.z * 50);
        var color = d.outlier ? CR : ACCENT;
        el('circle', {cx: cx, cy: cy, r: d.outlier ? 9 : 6, fill: color, opacity: 0.9}, svg);
        if (d.outlier) {
          pulse(svg, cx, cy, 9, CR, 0);
          txt(svg, cx, cy - 22, d.name, {fill: CR, size: 12, anchor: 'middle', mono: true, weight: 600});
          txt(svg, cx, cy - 38, 'z = ' + d.z.toFixed(1), {fill: CR, size: 11, anchor: 'middle', mono: true});
        }
      }
      txt(svg, STAGE_W / 2, 80, 'one cluster is far from the fleet.',
        {fill: HD, size: 18, anchor: 'middle', weight: 600});
    }
  });

  scenes.push({
    label: 'Fleet Score',
    duration: 7500,
    headline: 'One number for the whole fleet.',
    subcaption: 'Fleet Score is a <span class="accent">0 to 100</span> rollup of drift, outliers, health, and capacity.',
    paint: function (svg) {
      // Big number with arc
      var cx = STAGE_W / 2, cy = 280, R = 140;
      var score = 73;
      var grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
      // background arc
      el('circle', {cx: cx, cy: cy, r: R, fill: 'none', stroke: BD, 'stroke-width': 14}, svg);
      // foreground arc — uses dasharray to draw fraction
      var circ = 2 * Math.PI * R;
      el('circle', {
        cx: cx, cy: cy, r: R, fill: 'none',
        stroke: ACCENT, 'stroke-width': 14,
        'stroke-dasharray': circ, 'stroke-dashoffset': circ * (1 - score / 100),
        transform: 'rotate(-90 ' + cx + ' ' + cy + ')',
        'stroke-linecap': 'round'
      }, svg);
      txt(svg, cx, cy + 8, String(score), {
        fill: HD, size: 72, weight: 700, anchor: 'middle', mono: true
      });
      txt(svg, cx, cy + 44, 'grade ' + grade, {fill: MU, size: 14, anchor: 'middle'});
      // contributors
      var legend = [
        {label: 'critical findings', val: '-12', color: CR},
        {label: 'warning findings', val: '-8', color: WN},
        {label: 'cluster status', val: '-4', color: WN},
        {label: 'capacity strain', val: '-3', color: WN}
      ];
      for (var i = 0; i < legend.length; i++) {
        var lx = 130, ly = 110 + i * 32;
        el('rect', {x: lx, y: ly - 12, width: 6, height: 16, fill: legend[i].color}, svg);
        txt(svg, lx + 14, ly, legend[i].label, {fill: TX, size: 13});
        txt(svg, lx + 220, ly, legend[i].val, {fill: legend[i].color, size: 13, mono: true, anchor: 'end'});
      }
      txt(svg, 130, 90, 'how 73 was earned', {fill: MU, size: 11, weight: 600});
    }
  });

  scenes.push({
    label: 'Admission',
    duration: 9500,
    headline: 'The fleet enforces itself.',
    subcaption: 'A pod that drifts <span class="accent">away from the norm</span> gets warned in advisory mode and denied in enforce.',
    paint: function (svg) {
      // Left: incoming pod
      var px = 130, py = 240;
      el('rect', {x: px, y: py, width: 220, height: 200, fill: '#161b22', stroke: BD, rx: 8}, svg);
      txt(svg, px + 110, py + 26, 'incoming pod', {fill: MU, size: 11, anchor: 'middle', mono: true});
      txt(svg, px + 14, py + 60, 'image: nginx:1.27', {fill: TX, size: 12, mono: true});
      txt(svg, px + 14, py + 84, 'serviceAccount: default', {fill: TX, size: 12, mono: true});
      txt(svg, px + 14, py + 108, 'readOnlyRootFilesystem: ⌀', {fill: TX, size: 12, mono: true});
      txt(svg, px + 14, py + 132, 'runAsNonRoot: ⌀', {fill: TX, size: 12, mono: true});

      // Arrow
      el('line', {x1: 360, y1: 340, x2: 470, y2: 340, stroke: ACCENT, 'stroke-width': 2}, svg);
      el('polygon', {points: '470,335 480,340 470,345', fill: ACCENT}, svg);

      // Webhook
      var wx = 485, wy = 290;
      el('rect', {x: wx, y: wy, width: 200, height: 100, fill: '#11161d', stroke: ACCENT, 'stroke-width': 2, rx: 8}, svg);
      txt(svg, wx + 100, wy + 28, 'admission webhook', {fill: ACCENT, size: 12, anchor: 'middle', mono: true, weight: 600});
      txt(svg, wx + 100, wy + 58, 'baseline:', {fill: MU, size: 11, anchor: 'middle'});
      txt(svg, wx + 100, wy + 78, '91% digest-pinned · 86% named SA', {fill: TX, size: 11, anchor: 'middle', mono: true});

      // Arrow to verdict
      el('line', {x1: 695, y1: 340, x2: 805, y2: 340, stroke: WN, 'stroke-width': 2}, svg);
      el('polygon', {points: '805,335 815,340 805,345', fill: WN}, svg);

      // Verdict
      var vx = 820, vy = 270;
      el('rect', {x: vx, y: vy, width: 230, height: 150, fill: '#1d1a0d', stroke: WN, rx: 8}, svg);
      txt(svg, vx + 14, vy + 26, 'advisory mode', {fill: WN, size: 12, mono: true, weight: 600});
      txt(svg, vx + 14, vy + 52, '⚠ image not digest-pinned', {fill: WN, size: 11});
      txt(svg, vx + 14, vy + 72, '⚠ default ServiceAccount in use', {fill: WN, size: 11});
      txt(svg, vx + 14, vy + 92, '⚠ writable rootfs', {fill: WN, size: 11});
      txt(svg, vx + 14, vy + 120, 'allowed with warnings', {fill: MU, size: 11, mono: true});

      txt(svg, STAGE_W / 2, 100, 'pod admitted, operator notified, fleet stays consistent.',
        {fill: HD, size: 16, anchor: 'middle'});
    }
  });

  scenes.push({
    label: 'Alerts',
    duration: 9000,
    headline: 'Drift findings, AlertManager, Falco — one stream.',
    subcaption: 'Every signal lands in one alerts table with a shared <span class="accent">fingerprint dedup</span> so the dashboard never floods.',
    paint: function (svg) {
      var sources = [
        {label: 'AlertManager', color: ACCENT, y: 130},
        {label: 'Falco', color: PU, y: 230},
        {label: 'PolicyReport (Kyverno)', color: OK, y: 330},
        {label: 'Trivy CVEs', color: WN, y: 430}
      ];
      var sink = {x: 770, y: 280, w: 240, h: 200};
      for (var i = 0; i < sources.length; i++) {
        var s = sources[i];
        el('rect', {x: 80, y: s.y - 20, width: 200, height: 40, fill: '#161b22', stroke: s.color, rx: 6}, svg);
        txt(svg, 180, s.y + 4, s.label, {fill: s.color, size: 12, anchor: 'middle', mono: true});
        // line to sink
        el('path', {
          d: 'M 280 ' + s.y + ' C 500 ' + s.y + ', 600 ' + (sink.y + sink.h / 2) + ', ' + sink.x + ' ' + (sink.y + sink.h / 2),
          fill: 'none', stroke: s.color, 'stroke-width': 1.5, opacity: 0.6
        }, svg);
        pulse(svg, 280, s.y, 4, s.color, i * 0.3);
      }
      el('rect', {x: sink.x, y: sink.y, width: sink.w, height: sink.h, fill: '#11161d', stroke: ACCENT, 'stroke-width': 2, rx: 10}, svg);
      txt(svg, sink.x + sink.w / 2, sink.y + 30, '/api/alerts', {fill: ACCENT, size: 14, anchor: 'middle', mono: true, weight: 600});
      txt(svg, sink.x + sink.w / 2, sink.y + 56, 'fingerprint-keyed', {fill: MU, size: 11, anchor: 'middle'});
      var rows = ['HighMemory · prod-east', 'ContainerDrift · payments', 'require-labels · staging', 'CVE-2024-12345 · billing'];
      for (var r = 0; r < rows.length; r++) {
        txt(svg, sink.x + 16, sink.y + 90 + r * 22, rows[r], {fill: TX, size: 11, mono: true});
      }
      txt(svg, STAGE_W / 2, STAGE_H - 30, 'one stream. one SSE bus. one place to triage.',
        {fill: ACCENT, size: 13, anchor: 'middle'});
    }
  });

  scenes.push({
    label: 'Recommend',
    duration: 8500,
    headline: 'Leverage-ranked action list.',
    subcaption: '<span class="accent">fleetsweeper recommend</span> collapses identical fixes across clusters. Ten clusters fixed by one command beats one fix on one cluster.',
    paint: function (svg) {
      var items = [
        {sev: 'WARNING', sevC: WN, lev: 7, title: 'Pods missing resource limits',
         cmd: "kubectl get deploy -A -o json | jq '...'"},
        {sev: 'CRITICAL', sevC: CR, lev: 3, title: 'Default ServiceAccount in use',
         cmd: 'kubectl apply -f sa-template.yaml'},
        {sev: 'WARNING', sevC: WN, lev: 2, title: 'Image not digest-pinned',
         cmd: 'open runbook · https://runbooks.example/digest-pinning'}
      ];
      txt(svg, STAGE_W / 2, 70, 'next 3 highest-leverage fixes',
        {fill: HD, size: 16, anchor: 'middle', weight: 600});
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        var y = 130 + i * 130;
        el('rect', {x: 80, y: y, width: 940, height: 110, fill: '#161b22', stroke: BD, rx: 8}, svg);
        // severity badge
        el('rect', {x: 92, y: y + 16, width: 82, height: 22, fill: it.sevC, opacity: 0.12, rx: 4}, svg);
        txt(svg, 133, y + 31, it.sev, {fill: it.sevC, size: 11, anchor: 'middle', mono: true, weight: 700});
        // leverage chip
        el('rect', {x: 184, y: y + 16, width: 124, height: 22, fill: ACCENT, opacity: 0.1, rx: 4}, svg);
        txt(svg, 246, y + 31, 'leverage ' + it.lev + ' clusters', {
          fill: ACCENT, size: 11, anchor: 'middle', mono: true, weight: 600
        });
        // title
        txt(svg, 92, y + 60, it.title, {fill: HD, size: 14, weight: 600});
        // command
        el('rect', {x: 92, y: y + 76, width: 916, height: 24, fill: '#0d1117', stroke: BD, rx: 4}, svg);
        txt(svg, 102, y + 92, '$ ' + it.cmd, {fill: TX, size: 11, mono: true});
      }
    }
  });

  scenes.push({
    label: 'Whatchanged',
    duration: 7500,
    headline: 'After every deploy — what moved?',
    subcaption: '<span class="accent">fleetsweeper whatchanged</span> diffs two scans. New findings, cleared findings, per-cluster score deltas, sorted worst-first.',
    paint: function (svg) {
      txt(svg, 100, 90, 'Fleet score: 88 -> 73 (-15)', {fill: HD, size: 18, mono: true, weight: 700});
      // New
      txt(svg, 100, 140, 'new findings (3)', {fill: CR, size: 13, mono: true, weight: 600});
      var newF = [
        '[CRITICAL] prod-east — 5 nodes report NotReady',
        '[CRITICAL] prod-east — admission webhook unreachable',
        '[WARNING]  staging — 3 deployments without resource limits'
      ];
      for (var i = 0; i < newF.length; i++) {
        txt(svg, 120, 168 + i * 22, newF[i], {fill: TX, size: 12, mono: true});
      }
      // Cleared
      txt(svg, 100, 260, 'cleared findings (1)', {fill: OK, size: 13, mono: true, weight: 600});
      txt(svg, 120, 286, '[WARNING] staging — 12 containers without digest pin', {
        fill: MU, size: 12, mono: true
      });
      // Cluster deltas
      txt(svg, 100, 340, 'cluster score deltas', {fill: ACCENT, size: 13, mono: true, weight: 600});
      var deltas = [
        {name: 'prod-east', from: 91, to: 60, color: CR},
        {name: 'staging', from: 78, to: 82, color: OK}
      ];
      for (var d = 0; d < deltas.length; d++) {
        var dl = deltas[d];
        var dy = 370 + d * 32;
        txt(svg, 120, dy, dl.name, {fill: TX, size: 13, mono: true});
        txt(svg, 360, dy, dl.from + ' -> ' + dl.to, {fill: dl.color, size: 13, mono: true, weight: 600});
        txt(svg, 480, dy, (dl.to >= dl.from ? '+' : '') + (dl.to - dl.from), {fill: dl.color, size: 13, mono: true, weight: 700});
      }
      txt(svg, STAGE_W / 2, STAGE_H - 30, 'deploy gate it: --json | jq .new_findings | block on critical.',
        {fill: MU, size: 12, anchor: 'middle', mono: true});
    }
  });

  scenes.push({
    label: 'In-cluster',
    duration: 8000,
    headline: 'Ships as a Helm chart. CRDs. Webhook. Controller.',
    subcaption: 'Native Kubernetes: <span class="accent">ClusterScan</span> CRs schedule scans, leader election keeps one instance writing, doctor confirms it lights up.',
    paint: function (svg) {
      // Cluster boundary
      el('rect', {x: 100, y: 100, width: 900, height: 360, fill: 'none', stroke: BD, 'stroke-dasharray': '6 4', rx: 12}, svg);
      txt(svg, 120, 130, 'kubernetes cluster', {fill: MU, size: 11, mono: true});
      // pods
      var pods = [
        {x: 220, y: 220, label: 'Deployment\nfleetsweeper'},
        {x: 220, y: 360, label: 'ConfigMap\nbaseline'},
        {x: 500, y: 220, label: 'CRD\nClusterScan'},
        {x: 500, y: 360, label: 'CRD\nFleetDriftReport'},
        {x: 780, y: 220, label: 'ValidatingWebhook'},
        {x: 780, y: 360, label: 'Lease\nleader-election'}
      ];
      for (var p = 0; p < pods.length; p++) {
        var pd = pods[p];
        el('rect', {x: pd.x - 80, y: pd.y - 36, width: 160, height: 72, fill: '#161b22', stroke: ACCENT, 'stroke-width': 1, opacity: 0.95, rx: 6}, svg);
        var lines = pd.label.split('\n');
        for (var li = 0; li < lines.length; li++) {
          txt(svg, pd.x, pd.y - 8 + li * 18, lines[li], {fill: ACCENT, size: 12, anchor: 'middle', mono: true});
        }
      }
      // arrows from controller to CRDs
      el('line', {x1: 300, y1: 220, x2: 420, y2: 220, stroke: ACCENT, 'stroke-width': 1, opacity: 0.5}, svg);
      el('line', {x1: 580, y1: 220, x2: 700, y2: 220, stroke: ACCENT, 'stroke-width': 1, opacity: 0.5}, svg);
      pulse(svg, 220, 220, 12, ACCENT, 0);
    }
  });

  scenes.push({
    label: 'End',
    duration: 6500,
    headline: 'The fleet votes. Outliers get found.',
    subcaption: 'No rulebook. No babysitting. Drop it in, scan once, and the fleet starts defending itself.',
    paint: function (svg) {
      txt(svg, STAGE_W / 2, 100, 'fleetsweeper', {
        fill: ACCENT, size: 56, weight: 700, anchor: 'middle', mono: true
      });
      txt(svg, STAGE_W / 2, 140, 'the fleet is the policy', {
        fill: MU, size: 16, anchor: 'middle'
      });
      // Healed grid
      var positions = [
        [220, 280], [330, 220], [450, 260], [560, 200], [680, 250], [800, 230],
        [240, 380], [360, 420], [480, 380], [600, 430], [720, 380], [850, 410]
      ];
      for (var i = 0; i < positions.length; i++) {
        cluster(svg, positions[i][0], positions[i][1], 16, 'ok', null);
      }
      // CTA
      el('rect', {x: STAGE_W / 2 - 200, y: 470, width: 400, height: 56, fill: '#161b22', stroke: ACCENT, rx: 10}, svg);
      txt(svg, STAGE_W / 2, 495, 'helm install fleetsweeper fleetsweeper/fleetsweeper', {
        fill: ACCENT, size: 13, anchor: 'middle', mono: true
      });
      txt(svg, STAGE_W / 2, 514, 'github.com/dcadolph/fleetsweeper', {
        fill: MU, size: 11, anchor: 'middle', mono: true
      });
    }
  });

  // ---------- Utility: mode of a string array ----------
  function mode(arr) {
    var counts = {};
    var best = arr[0], bestN = 0;
    for (var i = 0; i < arr.length; i++) {
      var v = arr[i];
      counts[v] = (counts[v] || 0) + 1;
      if (counts[v] > bestN) { best = v; bestN = counts[v]; }
    }
    return best;
  }

  // ---------- Boot ----------
  function boot() {
    paintMarkers();
    wireScrubber();
    wireControls();
    startScene(0);
    ticker = window.setInterval(tick, 250);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
