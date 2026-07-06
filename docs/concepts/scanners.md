# Scanners

Fleetsweeper scans multiple Kubernetes clusters in parallel and compares
them across 24 dimensions. Each scanner is read-only, runs against a single
cluster at a time, and produces structured data for the report builder to
fold into the fleet picture.

| Scanner              | What it checks |
| -------------------- | -------------- |
| Kubernetes Version   | API server version divergence, with semver-aware severity |
| Namespaces           | Namespace lists, labels, and Pod Security Standards labels |
| Services             | All services across all namespaces, types, and ports |
| Ingresses            | Ingress resources, classes, TLS configuration, and hosts |
| RBAC                 | ClusterRoles, Roles, and all bindings |
| Pod Security         | PSS enforcement labels on every namespace |
| Network Policies     | NetworkPolicy coverage per namespace |
| Resource Quotas      | ResourceQuota and LimitRange objects |
| CRDs                 | Installed CustomResourceDefinitions |
| Node Resources       | Node count, allocatable CPU and memory, scheduling status |
| Node Health          | Node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure |
| Resource Utilization | Real-time CPU and memory from metrics-server |
| Events               | Warning events in the last hour, aggregated by reason |
| Workload Security    | Privileged containers, host namespaces, capabilities, seccomp, hostPath, runAs |
| RBAC Audit           | Cluster-admin bindings, wildcard rules, default-SA bindings, RoleBinding audit |
| Image Audit          | :latest tags, missing digest pins, image pull policies |
| Certificates         | TLS Secret, Ingress TLS, and webhook caBundle expiry |
| Deprecated APIs      | In-use API versions deprecated or removed in upcoming Kubernetes releases |
| Workload Coverage    | PDB and HPA coverage of replicated Deployments and StatefulSets |
| Cluster Info         | Node OS, kernel, runtime, and kubelet version drift within a cluster |
| Admission            | Webhook configurations with no healthy endpoints or expiring caBundles |
| Geo                  | Cluster location from node topology region and zone labels |
| Vulnerabilities      | Severity counts aggregated from Trivy Operator VulnerabilityReports |
| PolicyReport Ingest  | Fail and warn results from Kyverno, Gatekeeper, and other PolicyReport writers |

For every scanner, fleetsweeper compares the data across clusters and flags
divergences with severity levels (critical, warning, info). Findings name
the specific offending nodes, pods, bindings, and images so operators can
act without spelunking the JSON.

## Read-only by design

Every scanner uses `get` / `list` / `watch` only. Required permissions are
enumerated explicitly in [`deploy/rbac.yaml`](../../deploy/rbac.yaml).
Audit that file before deploying with cluster-admin credentials.

## Where to go next

- [Findings and remediation](findings.md). Severity calibration and `kubectl` outputs.
- [Outliers](outliers.md). Statistical detection layered on top of scanner data.
- [Architecture](../architecture.md). How scanner output flows through the rest of the pipeline.
