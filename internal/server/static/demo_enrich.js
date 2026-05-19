// Demo enrichment. When the server is in demo mode, the per-cluster detail
// endpoint returns an empty scanner_data block. This script wraps window.api
// so it transparently fills in plausible scanner sections for every cluster
// in the synthetic fleet, making the cluster detail page feel as rich in
// demo mode as it does against a real cluster.
//
// Pure frontend: nothing here changes server behavior. When running against
// a real fleet, the API already returns scanner_data and we leave it alone.

(function () {
  'use strict';

  var demoChecked = false;
  var demoActive = false;

  function isDemo(cb) {
    if (demoChecked) { cb(demoActive); return; }
    fetch('/api/geo').then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        demoActive = !!(d && d.demo);
        demoChecked = true;
        cb(demoActive);
      })
      .catch(function () { demoChecked = true; cb(false); });
  }

  var PRIOR_SCAN_ID = 'demo-scan-prior';

  function wrap() {
    if (typeof window.api !== 'function') {
      // The SPA inline script defines api() later; retry once the DOM finishes.
      return setTimeout(wrap, 50);
    }
    var original = window.api;
    window.api = async function (path) {
      // Synthesize an older scan record so the diff and scan-history pages
      // have something to compare against in demo mode.
      if (demoActive && typeof path === 'string') {
        if (/^\/scans\?/.test(path) || path === '/scans') {
          var scans = await original(path);
          if (Array.isArray(scans) && scans.length === 1 && scans[0] && scans[0].id) {
            scans.push(priorScanRecord(scans[0]));
          }
          return scans;
        }
        if (path === '/scans/' + PRIOR_SCAN_ID || path === '/scans/' + PRIOR_SCAN_ID + '/report') {
          var current = await original('/scans/demo-scan-0001' + (path.endsWith('/report') ? '/report' : ''));
          if (path.endsWith('/report')) return priorReport(current);
          return priorScanRecord(current);
        }
      }

      var data = await original(path);
      try {
        if (!demoActive) return data;
        if (typeof path !== 'string') return data;

        if (/^\/clusters\/[^\/]+\/detail$/.test(path)) {
          var name = decodeURIComponent(path.split('/')[2]);
          if (data && (!data.scanner_data || Object.keys(data.scanner_data).length === 0)) {
            data.scanner_data = synthesizeScannerData(name, data.health);
          }
        } else if (/^\/scans\/[^\/]+\/report$/.test(path)) {
          if (data && (!data.sections || Object.keys(data.sections).length === 0)) {
            data.sections = synthesizeSections(data);
          }
        }
      } catch (_) { /* never block real data on an enrichment failure */ }
      return data;
    };
  }

  // priorScanRecord builds a fake older scan record so the scan-history page
  // shows two entries and the diff page can compare them. The id is stable so
  // deep links work.
  function priorScanRecord(current) {
    var older = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    return {
      id: PRIOR_SCAN_ID,
      timestamp: older,
      clusters: current && current.clusters ? current.clusters.slice() : [],
      scanners: current && current.scanners ? current.scanners.slice() : [],
    };
  }

  // priorReport derives an older report from the current one by removing two
  // resolved-since findings and adding two that have since been fixed, so the
  // diff page shows meaningful "New" and "Resolved" sections.
  function priorReport(current) {
    if (!current) return current;
    var clone = JSON.parse(JSON.stringify(current));
    clone.timestamp = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    // The prior scan had fewer warning events on prod-us-east-1 (so a "worsening
    // trend" reads as believable) and one extra resolved-since finding.
    var resolved = [
      {
        title: 'staging-ap-northeast-2 had 4 deprecated API version(s)',
        description: 'Removed before next minor upgrade. Audit-only since.',
        severity: 'warning',
        cluster: 'staging-ap-northeast-2',
        scanner: 'deprecated-apis',
      },
      {
        title: 'prod-us-west-2 had 1 certificate expiring within 30 days',
        description: 'Renewed since last scan.',
        severity: 'warning',
        cluster: 'prod-us-west-2',
        scanner: 'certs',
      },
    ];
    // Drop any current finding that matches "resolved" titles so they appear
    // resolved on the diff.
    clone.findings = (clone.findings || []).filter(function (f) {
      return !resolved.some(function (r) { return r.cluster === f.cluster && r.title.split(' had ')[0] === f.cluster; });
    });
    clone.findings = (clone.findings || []).concat(resolved);
    return clone;
  }

  // synthesizeSections builds plausible per-scanner SectionReport entries for
  // every scanner referenced by the cluster_healths summary. Most are uniform;
  // a few intentionally diverge (version, security, network-policies) so the
  // dashboard's Divergent table has content to drill into.
  function synthesizeSections(report) {
    var clusters = (report && report.clusters) || [];
    var healths = {};
    (report.cluster_healths || []).forEach(function (h) { healths[h.name] = h; });

    function perCluster(builder) {
      var out = {};
      clusters.forEach(function (c) { out[c] = builder(c, healths[c] || {}); });
      return out;
    }

    var versionPerCluster = perCluster(function (_, h) {
      return { git_version: h.kubernetes_version || 'v1.31.3', platform: 'linux/amd64' };
    });
    var versions = {};
    clusters.forEach(function (c) { versions[versionPerCluster[c].git_version] = true; });
    var versionDiv = Object.keys(versions).length > 1 ? [{
      field: 'git_version',
      values: versionPerCluster,
    }] : [];

    var securityPerCluster = perCluster(function (_, h) {
      var status = h.status || 'healthy';
      var ns = h.namespace_count || 6;
      var unenf = status === 'critical' ? Math.max(2, Math.floor(ns * 0.35)) :
                  status === 'degraded' ? Math.max(1, Math.floor(ns * 0.20)) :
                  status === 'busy' ? Math.max(0, Math.floor(ns * 0.10)) : 0;
      return { unenforced_count: unenf, namespace_count: ns, enforced_count: ns - unenf };
    });
    var anyUnenf = clusters.some(function (c) { return securityPerCluster[c].unenforced_count > 0; });

    var netpolPerCluster = perCluster(function (_, h) {
      var status = h.status || 'healthy';
      var ns = h.namespace_count || 6;
      var without = status === 'critical' ? Math.max(2, Math.floor(ns * 0.4)) :
                    status === 'degraded' ? Math.max(1, Math.floor(ns * 0.25)) : 0;
      return { namespaces_without_policies: without, namespaces_with_policies: ns - without };
    });
    var anyNoNP = clusters.some(function (c) { return netpolPerCluster[c].namespaces_without_policies > 0; });

    return {
      version: {
        uniform: versionDiv.length === 0,
        divergences: versionDiv,
        per_cluster: versionPerCluster,
      },
      security: {
        uniform: !anyUnenf,
        divergences: anyUnenf ? [{ field: 'unenforced_count', values: securityPerCluster }] : [],
        per_cluster: securityPerCluster,
      },
      'network-policies': {
        uniform: !anyNoNP,
        divergences: anyNoNP ? [{ field: 'namespaces_without_policies', values: netpolPerCluster }] : [],
        per_cluster: netpolPerCluster,
      },
      'node-health': {
        uniform: false,
        divergences: [],
        per_cluster: perCluster(function (_, h) {
          return {
            healthy_nodes: h.healthy_nodes || h.node_count || 0,
            unhealthy_nodes: (h.node_count || 0) - (h.healthy_nodes || h.node_count || 0),
            memory_pressure_nodes: h.status === 'critical' ? 2 : 0,
          };
        }),
      },
      events: {
        uniform: false,
        divergences: [],
        per_cluster: perCluster(function (_, h) {
          return { warning_events: h.warning_events || 0, total_events: (h.warning_events || 0) + 200 };
        }),
      },
      metrics: {
        uniform: true,
        divergences: [],
        per_cluster: perCluster(function (_, h) {
          return { available: true, avg_cpu_percent: h.avg_cpu || 0, avg_memory_percent: h.avg_memory || 0 };
        }),
      },
      namespaces: {
        uniform: true,
        divergences: [],
        per_cluster: perCluster(function (_, h) { return { count: h.namespace_count || 0 }; }),
      },
    };
  }

  // synthesizeScannerData builds a coherent scanner_data block from the
  // health summary the server already returns, so every section the cluster
  // detail page knows how to render gets believable content.
  function synthesizeScannerData(cluster, h) {
    h = h || {};
    var status = h.status || 'healthy';
    var nodeCount = h.node_count || 3;
    var healthy = h.healthy_nodes != null ? h.healthy_nodes : nodeCount;
    var unhealthy = Math.max(0, nodeCount - healthy);
    var avgCPU = h.avg_cpu || 0;
    var avgMem = h.avg_memory || 0;
    var warnings = h.warning_events || 0;
    var nsCount = h.namespace_count || 6;
    var version = h.kubernetes_version || 'v1.31.3';

    var prefix = nodePrefix(cluster);
    var nodeNames = [];
    for (var i = 0; i < nodeCount; i++) {
      nodeNames.push(prefix + '-' + pad(i + 1));
    }
    var unhealthyNodes = nodeNames.slice(0, unhealthy);

    return {
      version: {
        git_version: version,
        platform: platformFor(cluster),
        major: version.split('.')[0].replace(/^v/, ''),
        minor: version.split('.')[1] || '31',
      },
      'node-health': nodeHealthBlock(cluster, nodeNames, unhealthyNodes, status),
      metrics: metricsBlock(nodeNames, avgCPU, avgMem, status),
      resources: resourcesBlock(nodeNames),
      events: eventsBlock(cluster, warnings, status),
      security: securityBlock(cluster, nsCount, status),
      'network-policies': networkPoliciesBlock(cluster, nsCount, status),
      rbac: rbacBlock(cluster),
      namespaces: namespacesBlock(cluster, nsCount),
      services: servicesBlock(cluster, nsCount),
      ingresses: ingressesBlock(cluster, nsCount),
      'resource-quotas': quotasBlock(nsCount, status),
      crds: { count: 18 + Math.floor(hashOf(cluster) % 12), names: crdNames(cluster) },
    };
  }

  function nodeHealthBlock(cluster, nodes, unhealthy, status) {
    var memPressure = status === 'critical' ? unhealthy : 0;
    var diskPressure = 0;
    var notReady = status === 'critical' && unhealthy ? Math.min(1, unhealthy) : 0;
    var rows = nodes.map(function (n, idx) {
      var isUnhealthy = idx < unhealthy.length;
      var hasMem = isUnhealthy && memPressure > 0 && idx < memPressure;
      return {
        name: n,
        ready: !(isUnhealthy && notReady > 0 && idx === 0),
        memory_pressure: !!hasMem,
        disk_pressure: false,
        pid_pressure: false,
        network_unavailable: false,
        unschedulable: false,
      };
    });
    return {
      node_count: nodes.length,
      healthy_nodes: nodes.length - unhealthy.length,
      unhealthy_nodes: unhealthy.length,
      memory_pressure_nodes: memPressure,
      disk_pressure_nodes: diskPressure,
      not_ready_nodes: notReady,
      unschedulable_nodes: 0,
      nodes: rows,
    };
  }

  function metricsBlock(nodes, avgCPU, avgMem, status) {
    var spread = status === 'critical' ? 8 : status === 'degraded' ? 5 : 3;
    var maxIdx = 0;
    var rows = nodes.map(function (n, i) {
      var pct = function (base) {
        var sign = (i + base.length) % 2 === 0 ? 1 : -1;
        return Math.max(1, Math.min(99, Math.round(base + sign * (spread - i % spread))));
      };
      var cpuPct = pct(avgCPU);
      var memPct = pct(avgMem);
      var cpuStr = (Math.round(cpuPct * 32)) + 'm';
      var memBytes = Math.round((memPct / 100) * 64) + 'Gi';
      if (cpuPct > maxIdx) maxIdx = cpuPct;
      return {
        name: n,
        cpu_usage: cpuStr,
        cpu_percent: cpuPct,
        memory_usage: memBytes,
        memory_percent: memPct,
      };
    });
    var maxCPUNode = rows.reduce(function (a, b) { return a.cpu_percent > b.cpu_percent ? a : b; }, rows[0]);
    var maxMemNode = rows.reduce(function (a, b) { return a.memory_percent > b.memory_percent ? a : b; }, rows[0]);
    return {
      available: true,
      avg_cpu_percent: avgCPU,
      avg_memory_percent: avgMem,
      max_cpu_percent: maxCPUNode.cpu_percent,
      max_cpu_node: maxCPUNode.name,
      max_memory_percent: maxMemNode.memory_percent,
      max_memory_node: maxMemNode.name,
      nodes: rows,
    };
  }

  function resourcesBlock(nodes) {
    var rows = nodes.map(function (n) {
      return {
        name: n,
        allocatable_cpu: '32',
        allocatable_memory: '64Gi',
        capacity_cpu: '32',
        capacity_memory: '64Gi',
        unschedulable: false,
      };
    });
    return {
      node_count: nodes.length,
      ready_nodes: nodes.length,
      total_allocatable_cpu: (nodes.length * 32) + ' cores',
      total_allocatable_memory: (nodes.length * 64) + 'Gi',
      nodes: rows,
    };
  }

  function eventsBlock(cluster, warnings, status) {
    var topReasons = warnings >= 50 ? [
      { reason: 'BackOff', count: Math.round(warnings * 0.42), event_count: Math.round(warnings * 0.42 / 3) },
      { reason: 'FailedScheduling', count: Math.round(warnings * 0.25), event_count: Math.round(warnings * 0.25 / 4) },
      { reason: 'Killing', count: Math.round(warnings * 0.14), event_count: Math.round(warnings * 0.14 / 2) },
      { reason: 'NetworkUnavailable', count: Math.round(warnings * 0.10), event_count: Math.round(warnings * 0.10 / 2) },
      { reason: 'NodeNotReady', count: Math.max(1, Math.round(warnings * 0.04)), event_count: 1 },
    ] : warnings >= 5 ? [
      { reason: 'BackOff', count: Math.round(warnings * 0.6), event_count: Math.round(warnings * 0.6 / 2) },
      { reason: 'FailedMount', count: Math.max(1, Math.round(warnings * 0.3)), event_count: 1 },
    ] : warnings > 0 ? [
      { reason: 'FailedMount', count: warnings, event_count: 1 },
    ] : [];

    var recent = topReasons.slice(0, 3).map(function (r, i) {
      return {
        namespace: ['app', 'platform', 'observability', 'ingress-nginx'][i % 4],
        kind: 'Pod',
        involved_object: workloadName(cluster, i) + '-' + randSuffix(cluster, i),
        reason: r.reason,
        message: messageFor(r.reason),
        count: Math.max(1, Math.floor(r.count / Math.max(1, r.event_count))),
        last_seen: minutesAgo(i + 1),
      };
    });

    return {
      total_events: warnings + 200,
      warning_events: warnings,
      normal_events: 200,
      top_warning_reasons: topReasons,
      recent_warnings: recent,
    };
  }

  function securityBlock(cluster, nsCount, status) {
    var unenforced = status === 'critical' ? Math.max(2, Math.floor(nsCount * 0.35)) :
                     status === 'degraded' ? Math.max(1, Math.floor(nsCount * 0.20)) :
                     status === 'busy' ? Math.max(0, Math.floor(nsCount * 0.10)) : 0;
    var names = namespaceList(cluster, nsCount);
    var namespaces = names.map(function (n, i) {
      var enforced = i >= unenforced;
      return {
        namespace: n,
        enforce: enforced ? 'baseline' : '',
        enforce_version: enforced ? 'latest' : '',
        audit: enforced ? 'baseline' : '',
        warn: enforced ? 'baseline' : '',
      };
    });
    return {
      enforced_count: nsCount - unenforced,
      unenforced_count: unenforced,
      namespace_count: nsCount,
      namespaces: namespaces,
    };
  }

  function networkPoliciesBlock(cluster, nsCount, status) {
    var without = status === 'critical' ? Math.max(2, Math.floor(nsCount * 0.4)) :
                  status === 'degraded' ? Math.max(1, Math.floor(nsCount * 0.25)) : 0;
    var policies = [];
    var names = namespaceList(cluster, nsCount).slice(without);
    names.forEach(function (n, i) {
      policies.push({
        namespace: n,
        name: 'default-deny',
        policy_types: ['Ingress', 'Egress'],
        ingress_rule_count: 0,
        egress_rule_count: 0,
      });
      if (i < 3) {
        policies.push({
          namespace: n,
          name: 'allow-' + n,
          policy_types: ['Ingress'],
          ingress_rule_count: 2,
          egress_rule_count: 0,
        });
      }
    });
    return {
      count: policies.length,
      namespaces_with_policies: nsCount - without,
      namespaces_without_policies: without,
      policies: policies,
    };
  }

  function rbacBlock(cluster) {
    var h = hashOf(cluster);
    var crCount = 60 + (h % 30);
    var rCount = 12 + (h % 8);
    var crbCount = 25 + (h % 10);
    var rbCount = 30 + (h % 14);
    var bindings = [
      { kind: 'ClusterRoleBinding', namespace: '', name: 'cluster-admin', role_ref: 'cluster-admin', subject_count: 1 },
      { kind: 'ClusterRoleBinding', namespace: '', name: 'system:basic-user', role_ref: 'system:basic-user', subject_count: 1 },
      { kind: 'RoleBinding', namespace: 'kube-system', name: 'system:controller:bootstrap-signer', role_ref: 'system:controller:bootstrap-signer', subject_count: 1 },
    ];
    var roles = [
      { kind: 'ClusterRole', namespace: '', name: 'cluster-admin', rule_count: 1 },
      { kind: 'ClusterRole', namespace: '', name: 'view', rule_count: 36 },
      { kind: 'Role', namespace: 'kube-system', name: 'system:controller:bootstrap-signer', rule_count: 2 },
    ];
    return {
      cluster_role_count: crCount,
      role_count: rCount,
      cluster_role_binding_count: crbCount,
      role_binding_count: rbCount,
      roles: roles,
      bindings: bindings,
    };
  }

  function namespacesBlock(cluster, nsCount) {
    var names = namespaceList(cluster, nsCount);
    var labels = {};
    names.forEach(function (n) {
      labels[n] = { 'kubernetes.io/metadata.name': n };
    });
    return { count: nsCount, names: names, labels: labels };
  }

  function servicesBlock(cluster, nsCount) {
    var names = namespaceList(cluster, nsCount);
    var rows = [];
    names.slice(0, 6).forEach(function (ns, i) {
      rows.push({
        namespace: ns,
        name: workloadName(cluster, i),
        type: i % 3 === 0 ? 'LoadBalancer' : 'ClusterIP',
        ports: [{ name: 'http', port: 80, protocol: 'TCP' }, { name: 'https', port: 443, protocol: 'TCP' }],
      });
    });
    return { count: rows.length, services: rows };
  }

  function ingressesBlock(cluster, nsCount) {
    var rows = namespaceList(cluster, Math.min(4, nsCount)).map(function (ns, i) {
      return {
        namespace: ns,
        name: ns + '-ing',
        ingress_class_name: 'nginx',
        hosts: [ns + '.' + cluster + '.example.com'],
        tls: i % 2 === 0,
      };
    });
    return { count: rows.length, ingresses: rows };
  }

  function quotasBlock(nsCount, status) {
    return {
      quota_count: status === 'healthy' ? Math.max(1, Math.floor(nsCount / 2)) : 0,
      limit_range_count: status === 'healthy' ? Math.max(1, Math.floor(nsCount / 3)) : 0,
      namespaces_with_quotas: status === 'healthy' ? Math.max(1, Math.floor(nsCount / 2)) : 0,
      quotas: [],
    };
  }

  function crdNames(cluster) {
    return [
      'certificates.cert-manager.io',
      'clusterissuers.cert-manager.io',
      'servicemonitors.monitoring.coreos.com',
      'prometheuses.monitoring.coreos.com',
      'helmreleases.helm.toolkit.fluxcd.io',
      'kustomizations.kustomize.toolkit.fluxcd.io',
      'applications.argoproj.io',
      'fleetdriftreports.fleetsweeper.io',
    ];
  }

  function namespaceList(cluster, count) {
    var base = ['kube-system', 'kube-public', 'default', 'observability', 'ingress-nginx', 'cert-manager', 'argocd', 'platform', 'app', 'cache', 'payments', 'search', 'cart', 'pos-system'];
    return base.slice(0, count);
  }

  function platformFor(cluster) {
    if (cluster.indexOf('gke') >= 0 || cluster.indexOf('gcp') >= 0) return 'linux/amd64';
    if (cluster.indexOf('azure') >= 0) return 'linux/amd64';
    return 'linux/amd64';
  }

  function nodePrefix(cluster) {
    if (cluster.indexOf('aws') >= 0 || cluster.indexOf('eks') >= 0 || cluster.indexOf('prod-us') >= 0) return 'ip-10-0';
    if (cluster.indexOf('gke') >= 0 || cluster.indexOf('gcp') >= 0) return 'gke-node';
    if (cluster.indexOf('azure') >= 0) return 'aks-node';
    return 'node';
  }

  function workloadName(cluster, i) {
    var pool = ['api', 'web', 'worker', 'cache', 'gateway', 'auth', 'billing'];
    return pool[(hashOf(cluster) + i) % pool.length];
  }

  function messageFor(reason) {
    var m = {
      BackOff: 'Back-off restarting failed container',
      FailedScheduling: '0/3 nodes available: insufficient memory',
      Killing: 'Stopping container due to failed liveness probe',
      FailedMount: 'MountVolume.SetUp failed for volume "config"',
      NetworkUnavailable: 'kubelet network plugin reports not ready',
      NodeNotReady: 'Node status changed to NotReady',
    };
    return m[reason] || 'See kubectl events for details';
  }

  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function hashOf(s) { var h = 5381; for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return h; }
  function randSuffix(cluster, i) {
    var alphabet = 'abcdefghjkmnpqrstvwxyz0123456789';
    var h = hashOf(cluster + ':' + i);
    var out = '';
    for (var k = 0; k < 5; k++) { out += alphabet[h % alphabet.length]; h = Math.floor(h / alphabet.length); }
    return out;
  }
  function minutesAgo(n) {
    var d = new Date(Date.now() - n * 60 * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  }

  isDemo(function (active) {
    if (active) wrap();
  });
})();
