# Scanners

Fleetsweeper scans multiple Kubernetes clusters in parallel and compares
them across 24 dimensions. Each scanner is read-only, runs against a single
cluster at a time, and produces structured data for the report builder to
fold into the fleet picture.

| Scanner              | Key                 | What it checks                                                                 |
| -------------------- | ------------------- | ------------------------------------------------------------------------------ |
| Kubernetes Version   | `version`           | API server version divergence, with semver-aware severity                      |
| Namespaces           | `namespaces`        | Namespace lists and all namespace labels                                       |
| Services             | `services`          | All services across all namespaces, types, and ports                           |
| Ingresses            | `ingresses`         | Ingress resources, classes, TLS configuration, and hosts                       |
| RBAC                 | `rbac`              | ClusterRoles, Roles, and all bindings                                          |
| Pod Security         | `security`          | PSS enforce, audit, and warn labels on every namespace                         |
| Network Policies     | `network-policies`  | NetworkPolicy coverage per namespace                                           |
| Resource Quotas      | `resource-quotas`   | ResourceQuota and LimitRange objects                                           |
| CRDs                 | `crds`              | Installed CustomResourceDefinitions                                            |
| Node Resources       | `resources`         | Node count, allocatable CPU and memory, scheduling status                      |
| Node Health          | `node-health`       | Node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure              |
| Resource Utilization | `metrics`           | Real-time CPU and memory from metrics-server                                   |
| Events               | `events`            | Warning events in the last hour, aggregated by reason                          |
| Workload Security    | `workload-security` | Privileged containers, host namespaces, capabilities, seccomp, hostPath, runAs |
| RBAC Audit           | `rbac-audit`        | Cluster-admin bindings, wildcard rules, default-SA bindings, RoleBinding audit |
| Image Audit          | `image-audit`       | :latest tags, missing digest pins, image pull policies                         |
| Certificates         | `certs`             | TLS Secret, Ingress TLS, and webhook caBundle expiry                           |
| Deprecated APIs      | `deprecated-apis`   | In-use API versions deprecated or removed in upcoming Kubernetes releases      |
| Workload Coverage    | `workload-coverage` | PDB and HPA coverage of replicated Deployments and StatefulSets                |
| Cluster Info         | `cluster-info`      | Node OS, kernel, runtime, and kubelet version drift within a cluster           |
| Admission            | `admission`         | Webhook configurations with no healthy endpoints or expiring caBundles         |
| Geo                  | `geo`               | Cluster location from node topology region and zone labels                     |
| Vulnerabilities      | `vulnerabilities`   | Severity counts aggregated from Trivy Operator VulnerabilityReports            |
| PolicyReport Ingest  | `policy-reports`    | Fail and warn results from Kyverno, Gatekeeper, and other PolicyReport writers |

For every scanner, fleetsweeper compares the data across clusters and flags
divergences with severity levels (critical, warning, info). Findings name
the specific offending nodes, pods, bindings, and images so operators can
act without spelunking the JSON.

## Membership, not just counts

Three scanners report lists, and fleetsweeper compares them as sets of
names, not only as counts. A name that at least 60% of the clusters have is
part of the consensus, and a cluster that lacks it gets a finding naming
what is missing.

| Set | Members | Rule | Severity |
| --- | --- | --- | --- |
| `crd_names` | CRD names | `crds/missing-consensus` | warning |
| `service_names` | `namespace/name` of each service | `services/missing-consensus` | info |
| `ingress_classes` | Ingress classes in use | `ingresses/missing-consensus` | info |

A cluster with no ingresses at all is left out of the ingress-class
comparison, since it uses no class rather than the wrong one. Within a
cohort the rules read `crds/cohort-missing-consensus` and so on.
`fleetsweeper compare` and `fleetsweeper watch` list, for a cluster whose
set finding persisted, the members it newly lacks and the ones it got back.

## Vulnerabilities and policy reports

The critical and high CVE counts from Trivy Operator and the PolicyReport
failure count are compared across the fleet like any other count, under
their own rules: `vulnerabilities/critical-outlier` and
`policy-reports/fail-outlier` (warning), and `vulnerabilities/high-outlier`
(info). A cluster where Trivy Operator or the PolicyReport CRDs are not
installed reports `available: false`, and its counts stay out of the fleet
population, so it never reads as a cluster with zero vulnerabilities.

Independent of the fleet, `vulnerabilities/critical-present` fires at info
severity on every cluster whose reports list at least one critical CVE,
naming the worst images.

## Read-only by design

Every scanner uses `get` / `list` / `watch` only. Required permissions are
enumerated explicitly in [`deploy/rbac.yaml`](../../deploy/rbac.yaml).
Audit that file before deploying with cluster-admin credentials.

## Where to go next

- [Findings and remediation](findings.md). Severity calibration and `kubectl` outputs.
- [Outliers](outliers.md). Statistical detection layered on top of scanner data.
- [Architecture](../architecture.md). How scanner output flows through the rest of the pipeline.
