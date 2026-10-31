// Glossary text for tooltips, and the legacy remediation commands shown when a
// finding from an older scan carries no server-supplied remediation.

// TIPS maps scanners, fields, summary cards, and severities to tooltip text.
export const TIPS = {
  // Summary cards.
  clusters:'Total Kubernetes clusters scanned in this run.',
  uniform:'Scanners where every cluster returned identical data. No action needed.',
  divergent:'Scanners where at least one cluster differs from the others. Investigate to determine if the difference is intentional.',
  critical:'High-severity findings that likely need immediate attention: version mismatches, node pressure, resource exhaustion.',
  warnings:'Medium-severity findings: missing policies, quota gaps, elevated utilization.',
  issues:'Total individual divergence points across all scanners.',
  // Scanner names.
  'version':'Compares Kubernetes API server versions (major.minor.patch) across all clusters.',
  'namespaces':'Lists all namespaces per cluster and compares the sets. Detects missing namespaces that should exist fleet-wide.',
  'services':'Enumerates all Services (ClusterIP, NodePort, LoadBalancer) across all namespaces.',
  'ingresses':'Lists Ingress resources, their classes, hosts, and TLS configuration.',
  'rbac':'Compares ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings. Detects permission drift.',
  'security':'Checks Pod Security Standards labels (enforce, audit, warn) on every namespace.',
  'network-policies':'Counts NetworkPolicy resources per namespace. Identifies namespaces with no network segmentation.',
  'resource-quotas':'Lists ResourceQuota and LimitRange objects. Detects clusters with no resource limits.',
  'node-health':'Reads node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable.',
  'metrics':'Queries the metrics-server API for real-time CPU and memory utilization per node.',
  'events':'Collects Warning-type Kubernetes events. Aggregates by reason to surface recurring issues.',
  'workload-security':'Audits pod security contexts: privileged containers, host namespace access, root users, Linux capability additions, writable root filesystems.',
  'rbac-audit':'Deep RBAC analysis: wildcard permission rules, non-system cluster-admin bindings, default service account grants, automounted tokens.',
  'image-audit':'Checks container image references for :latest tags, missing tags, and absent digest pins (@sha256:).',
  'privileged_containers':'Containers running with privileged=true. Full host kernel access.',
  'host_network_pods':'Pods sharing the host network namespace. Can see all node traffic.',
  'host_pid_pods':'Pods sharing the host PID namespace. Can see and signal all node processes.',
  'run_as_root_containers':'Init and regular containers whose effective runAsUser is 0, set on the container or inherited from the pod.',
  'run_as_non_root_containers':'Init and regular containers explicitly non-root: an effective runAsUser above 0, or an unset one under an effective runAsNonRoot of true.',
  'run_as_unknown_containers':'Init and regular containers whose spec does not settle the user, so only the image decides. Counted as not non-root.',
  'baseline_containers':'Init and regular containers scanned. Ephemeral debug containers are left out, since admission never sees them.',
  'capability_additions':'Containers requesting Linux capabilities beyond the default set (NET_ADMIN, SYS_PTRACE, etc.).',
  'cluster_admin_bindings':'ClusterRoleBindings granting cluster-admin to non-system accounts. Unrestricted cluster access.',
  'wildcard_rules':'RBAC rules using * for verbs or resources. Broader than most workloads need.',
  'latest_tag':'Containers using :latest or no tag. Prevents tracking deployed versions.',
  'no_digest':'Containers without @sha256: digest pin. Tag content can change silently.',
  'crds':'Lists all CustomResourceDefinitions. Detects add-on or operator drift across clusters.',
  'resources':'Reports node count, allocatable CPU/memory, and scheduling status.',
  // Fields.
  'git_version':'The full Kubernetes version string reported by the API server (e.g. v1.31.2).',
  'avg_cpu_percent':'Average CPU utilization across all nodes in the cluster, as a percentage of allocatable CPU.',
  'avg_memory_percent':'Average memory utilization across all nodes, as a percentage of allocatable memory.',
  'max_cpu_percent':'Highest CPU utilization on any single node in the cluster.',
  'max_memory_percent':'Highest memory utilization on any single node in the cluster.',
  'healthy_nodes':'Nodes reporting Ready=True with no pressure conditions (MemoryPressure, DiskPressure, PIDPressure all False).',
  'unhealthy_nodes':'Nodes with at least one pressure condition or not in Ready state.',
  'memory_pressure_nodes':'Nodes where kubelet reports MemoryPressure=True. The node is running low on memory and may start evicting pods.',
  'disk_pressure_nodes':'Nodes where kubelet reports DiskPressure=True. Disk space is critically low.',
  'not_ready_nodes':'Nodes not reporting Ready=True. Workloads cannot be scheduled here.',
  'unschedulable_nodes':'Nodes that have been cordoned (spec.unschedulable=true). No new pods will be scheduled.',
  'enforced_count':'Namespaces whose pod-security.kubernetes.io/enforce label is restricted or baseline.',
  'unenforced_count':'Namespaces missing the PSS enforce label or set to privileged, which enforces nothing. Pods can run with any security context.',
  'namespaces_with_policies':'Namespaces that have at least one NetworkPolicy resource.',
  'namespaces_without_policies':'Namespaces with zero NetworkPolicy resources. All pod-to-pod traffic is unrestricted.',
  'warning_events':'Number of Kubernetes events with type=Warning in this cluster.',
  'quota_count':'Number of ResourceQuota objects across all namespaces.',
  'cluster_role_count':'Number of ClusterRole objects (cluster-wide RBAC permissions).',
  'node_count':'Total number of nodes registered in the cluster.',
  // Severity levels.
  'sev_critical':'Requires immediate attention. May cause outages, security exposure, or data loss if not addressed.',
  'sev_warning':'Should be investigated soon. May indicate drift, missing best practices, or emerging resource pressure.',
  'sev_info':'Informational. No action required. Confirms expected state or notes minor differences.'
};

// REMEDIATION maps a scanner and title keyword to kubectl commands.
const REMEDIATION = {
  'node-health_memory pressure':[
    'kubectl --context {cluster} describe nodes | grep -A5 MemoryPressure',
    'kubectl --context {cluster} top nodes',
    'kubectl --context {cluster} get pods --all-namespaces --sort-by=.status.containerStatuses[0].resources.requests.memory -o wide'
  ],
  'node-health_disk pressure':[
    'kubectl --context {cluster} describe nodes | grep -A5 DiskPressure',
    'kubectl --context {cluster} get pods --all-namespaces -o wide | grep Evicted',
    'kubectl --context {cluster} exec -it <node-debug-pod> -- df -h'
  ],
  'node-health_not ready':[
    'kubectl --context {cluster} get nodes',
    'kubectl --context {cluster} describe node <node-name> | grep -A10 Conditions',
    'kubectl --context {cluster} get events --field-selector involvedObject.kind=Node --sort-by=.lastTimestamp'
  ],
  'version_different':[
    'kubectl --context {cluster} version --short',
    'kubectl --context {cluster} get nodes -o wide'
  ],
  'metrics_memory':[
    'kubectl --context {cluster} top nodes',
    'kubectl --context {cluster} top pods --all-namespaces --sort-by=memory | head -20',
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[] | select(.spec.containers[].resources.requests.memory == null)] | length\''
  ],
  'metrics_cpu':[
    'kubectl --context {cluster} top nodes',
    'kubectl --context {cluster} top pods --all-namespaces --sort-by=cpu | head -20'
  ],
  'security_enforcement':[
    'kubectl --context {cluster} get namespaces -L pod-security.kubernetes.io/enforce',
    'kubectl --context {cluster} label namespace <ns> pod-security.kubernetes.io/enforce=baseline',
    'kubectl --context {cluster} label namespace <ns> pod-security.kubernetes.io/warn=restricted'
  ],
  'network-policies_no network':[
    'kubectl --context {cluster} get networkpolicies --all-namespaces',
    'kubectl --context {cluster} get namespaces -o custom-columns=NAME:.metadata.name',
    'kubectl --context {cluster} apply -f <deny-all-netpol.yaml> -n <namespace>'
  ],
  'resource-quotas_no resource':[
    'kubectl --context {cluster} get resourcequotas --all-namespaces',
    'kubectl --context {cluster} get limitranges --all-namespaces',
    'kubectl --context {cluster} apply -f <resource-quota.yaml> -n <namespace>'
  ],
  'events_warning':[
    'kubectl --context {cluster} get events --all-namespaces --field-selector type=Warning --sort-by=.lastTimestamp | tail -30',
    'kubectl --context {cluster} get events --all-namespaces --field-selector reason=OOMKilling',
    'kubectl --context {cluster} get events --all-namespaces --field-selector reason=FailedScheduling'
  ],
  'namespaces_varies':[
    'kubectl --context {cluster} get namespaces',
    'diff <(kubectl --context cluster-a get ns -o name | sort) <(kubectl --context cluster-b get ns -o name | sort)'
  ],
  'rbac_differs':[
    'kubectl --context {cluster} get clusterroles -o name | sort',
    'kubectl --context {cluster} get clusterrolebindings -o name | sort',
    'diff <(kubectl --context cluster-a get clusterroles -o name | sort) <(kubectl --context cluster-b get clusterroles -o name | sort)'
  ],
  'workload-security_privileged':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + "/" + .metadata.name] | unique[]\'',
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'.items[] | select(.spec.hostNetwork==true) | .metadata.namespace + "/" + .metadata.name\''
  ],
  'workload-security_host':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | .metadata.namespace + "/" + .metadata.name\''
  ],
  'workload-security_root':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[] | select(.spec.containers[].securityContext.runAsNonRoot!=true) | .metadata.namespace + "/" + .metadata.name] | unique[]\''
  ],
  'workload-security_capabilities':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[] | select(.spec.containers[].securityContext.capabilities.add!=null) | {pod:(.metadata.namespace+"/"+.metadata.name),caps:.spec.containers[].securityContext.capabilities.add}]\''
  ],
  'rbac-audit_admin':[
    'kubectl --context {cluster} get clusterrolebindings -o json | jq \'.items[] | select(.roleRef.name=="cluster-admin") | {name:.metadata.name,subjects:.subjects[].name}\'',
    'kubectl --context {cluster} auth can-i --list --as=system:serviceaccount:<ns>:<sa>'
  ],
  'rbac-audit_wildcard':[
    'kubectl --context {cluster} get clusterroles -o json | jq \'[.items[] | select(.rules[]?.verbs[]?=="*" or .rules[]?.resources[]?=="*") | .metadata.name]\''
  ],
  'rbac-audit_default':[
    'kubectl --context {cluster} get rolebindings,clusterrolebindings --all-namespaces -o json | jq \'[.items[] | select(.subjects[]? | .name=="default" and .kind=="ServiceAccount") | .metadata.name]\''
  ],
  'image-audit_latest':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[].spec.containers[] | select(.image | test(":latest$") or (test(":")|not)) | .image] | unique[]\''
  ],
  'image-audit_digest':[
    'kubectl --context {cluster} get pods --all-namespaces -o json | jq \'[.items[].spec.containers[] | select(.image | test("@sha256:")|not) | .image] | unique[] \' | head -20'
  ]
};

// legacyRemediation returns kubectl commands for a finding without a
// server-supplied remediation, matched by scanner and title keyword, or null.
export function legacyRemediation(f){
  let key='';
  const t=(f.title||'').toLowerCase();
  if(f.scanner==='node-health'&&t.indexOf('memory pressure')>=0)key='node-health_memory pressure';
  else if(f.scanner==='node-health'&&t.indexOf('disk pressure')>=0)key='node-health_disk pressure';
  else if(f.scanner==='node-health'&&t.indexOf('not ready')>=0)key='node-health_not ready';
  else if(f.scanner==='version')key='version_different';
  else if(f.scanner==='metrics'&&t.indexOf('memory')>=0)key='metrics_memory';
  else if(f.scanner==='metrics'&&t.indexOf('cpu')>=0)key='metrics_cpu';
  else if(f.scanner==='security')key='security_enforcement';
  else if(f.scanner==='network-policies')key='network-policies_no network';
  else if(f.scanner==='resource-quotas')key='resource-quotas_no resource';
  else if(f.scanner==='events')key='events_warning';
  else if(f.scanner==='namespaces')key='namespaces_varies';
  else if(f.scanner==='rbac')key='rbac_differs';
  else if(f.scanner==='workload-security'&&t.indexOf('privileged')>=0)key='workload-security_privileged';
  else if(f.scanner==='workload-security'&&t.indexOf('host')>=0)key='workload-security_host';
  else if(f.scanner==='workload-security'&&t.indexOf('root')>=0)key='workload-security_root';
  else if(f.scanner==='workload-security'&&t.indexOf('capabilit')>=0)key='workload-security_capabilities';
  else if(f.scanner==='rbac-audit'&&t.indexOf('cluster-admin')>=0)key='rbac-audit_admin';
  else if(f.scanner==='rbac-audit'&&t.indexOf('wildcard')>=0)key='rbac-audit_wildcard';
  else if(f.scanner==='rbac-audit'&&t.indexOf('default')>=0)key='rbac-audit_default';
  else if(f.scanner==='image-audit'&&t.indexOf('latest')>=0)key='image-audit_latest';
  else if(f.scanner==='image-audit'&&t.indexOf('digest')>=0)key='image-audit_digest';
  if(!key)return null;
  const cmds=REMEDIATION[key];
  if(!cmds)return null;
  const cluster=f.cluster||'{cluster}';
  return cmds.map(function(c){return c.replace(/\{cluster\}/g,cluster)});
}

// tip returns the tooltip text for a key, or the empty string.
export function tip(key) {
  return TIPS[key] || '';
}
