package server

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/admission"
	"github.com/dcadolph/fleetsweeper/internal/scanner/certs"
	"github.com/dcadolph/fleetsweeper/internal/scanner/clusterinfo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/crd"
	"github.com/dcadolph/fleetsweeper/internal/scanner/deprecatedapis"
	"github.com/dcadolph/fleetsweeper/internal/scanner/events"
	"github.com/dcadolph/fleetsweeper/internal/scanner/geo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/imageaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/ingress"
	"github.com/dcadolph/fleetsweeper/internal/scanner/metrics"
	"github.com/dcadolph/fleetsweeper/internal/scanner/namespace"
	"github.com/dcadolph/fleetsweeper/internal/scanner/networkpolicy"
	"github.com/dcadolph/fleetsweeper/internal/scanner/nodehealth"
	"github.com/dcadolph/fleetsweeper/internal/scanner/policyreportingest"
	"github.com/dcadolph/fleetsweeper/internal/scanner/quota"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbac"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbacaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/resources"
	"github.com/dcadolph/fleetsweeper/internal/scanner/security"
	"github.com/dcadolph/fleetsweeper/internal/scanner/service"
	"github.com/dcadolph/fleetsweeper/internal/scanner/version"
	"github.com/dcadolph/fleetsweeper/internal/scanner/vulnerabilities"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadcoverage"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadsec"
)

// demoStepCluster is the cluster whose RBAC footprint steps up partway through the demo series,
// so the drift ledger and the history charts have a real change to show.
const demoStepCluster = "prod-us-west-2"

// demoShape is the size a cohort's clusters are built around.
type demoShape struct {
	// Nodes is the node count.
	Nodes int
	// AppNamespaces are the application namespaces every member runs.
	AppNamespaces []string
	// Ingresses is the ingress count.
	Ingresses int
	// CRDGroups are the API groups of the CRDs every member installs.
	CRDGroups []string
	// ClusterRoles is the ClusterRole count.
	ClusterRoles int
	// CPU is the base CPU utilization percent.
	CPU float64
	// Memory is the base memory utilization percent.
	Memory float64
}

// demoShapes maps a cohort to its shape. Cohorts differ in size the way production, development,
// site, and edge clusters do, and members of one cohort share their namespaces and CRDs.
var demoShapes = map[string]demoShape{ //nolint:gochecknoglobals // Not modified, fixed demo data.
	"prod": {
		Nodes: 12, Ingresses: 16, ClusterRoles: 62, CPU: 61, Memory: 64,
		AppNamespaces: []string{"payments", "checkout", "catalog", "search", "accounts", "orders", "inventory", "pricing",
			"notifications", "gateway", "auth", "reporting", "media", "recommendations"},
		CRDGroups: []string{"cert-manager.io", "monitoring.coreos.com", "argoproj.io", "external-secrets.io", "keda.sh", "networking.istio.io"},
	},
	"nonprod": {
		Nodes: 6, Ingresses: 8, ClusterRoles: 58, CPU: 39, Memory: 46,
		AppNamespaces: []string{"payments", "checkout", "catalog", "search", "accounts", "orders", "sandbox", "ci-runners"},
		CRDGroups:     []string{"cert-manager.io", "monitoring.coreos.com", "argoproj.io", "external-secrets.io"},
	},
	"sites": {
		Nodes: 4, Ingresses: 6, ClusterRoles: 52, CPU: 47, Memory: 51,
		AppNamespaces: []string{"pos", "kiosk", "sensors", "local-cache", "telemetry", "sync"},
		CRDGroups:     []string{"cert-manager.io", "monitoring.coreos.com", "fleet.cattle.io"},
	},
	"edge": {
		Nodes: 3, Ingresses: 4, ClusterRoles: 50, CPU: 52, Memory: 55,
		AppNamespaces: []string{"ingest", "relay", "telemetry", "local-cache", "sync"},
		CRDGroups:     []string{"cert-manager.io", "monitoring.coreos.com", "fleet.cattle.io"},
	},
}

// demoSystemNamespaces are the namespaces every cluster carries.
var demoSystemNamespaces = []string{"default", "kube-node-lease", "kube-public", "kube-system"} //nolint:gochecknoglobals // Not modified.

// demoProfile is one cluster at one scan of the series: its fixed traits and the incidents in
// effect at that scan.
type demoProfile struct {
	// C is the cluster.
	C demoCluster
	// Shape is the cluster's cohort shape.
	Shape demoShape
	// I is the scan index, oldest first.
	I int
	// N is the series length.
	N int
	// At is the scan time.
	At time.Time
	// Latest is when the newest scan of the series ran.
	Latest time.Time
}

// recent reports whether the scan is among the last k of the series.
func (p demoProfile) recent(k int) bool {
	return p.I >= p.N-k
}

// between reports whether the scan index is in [from, to) counted back from the newest scan,
// so between(14, 10) is true for the scans 14 to 11 before the newest.
func (p demoProfile) between(from, to int) bool {
	return p.I >= p.N-from && p.I < p.N-to
}

// demoResults returns every scanner's result for every demo cluster at scan i of demoScans,
// taken at at, with latest the time of the newest scan.
func demoResults(i int, at, latest time.Time) map[string]map[string]scanner.Result {
	out := make(map[string]map[string]scanner.Result, len(demoFleet()))
	for _, c := range demoFleet() {
		p := demoProfile{C: c, Shape: demoShapes[c.Cohort], I: i, N: demoScans, At: at, Latest: latest}
		results := map[string]scanner.Result{
			version.Name:            ok(version.Name, demoVersionData(p)),
			nodehealth.Name:         ok(nodehealth.Name, demoNodeHealth(p)),
			resources.Name:          ok(resources.Name, demoResources(p)),
			metrics.Name:            ok(metrics.Name, demoMetrics(p)),
			events.Name:             ok(events.Name, demoEvents(p)),
			namespace.Name:          ok(namespace.Name, demoNamespaces(p)),
			security.Name:           ok(security.Name, demoSecurity(p)),
			networkpolicy.Name:      ok(networkpolicy.Name, demoNetworkPolicies(p)),
			quota.Name:              ok(quota.Name, demoQuotas(p)),
			service.Name:            ok(service.Name, demoServices(p)),
			ingress.Name:            ok(ingress.Name, demoIngresses(p)),
			crd.Name:                ok(crd.Name, demoCRDs(p)),
			rbac.Name:               ok(rbac.Name, demoRBAC(p)),
			rbacaudit.Name:          ok(rbacaudit.Name, demoRBACAudit(p)),
			workloadsec.Name:        ok(workloadsec.Name, demoWorkloadSecurity(p)),
			imageaudit.Name:         ok(imageaudit.Name, demoImageAudit(p)),
			certs.Name:              ok(certs.Name, demoCerts(p)),
			deprecatedapis.Name:     ok(deprecatedapis.Name, demoDeprecated(p)),
			workloadcoverage.Name:   ok(workloadcoverage.Name, demoCoverage(p)),
			admission.Name:          ok(admission.Name, demoAdmission(p)),
			vulnerabilities.Name:    ok(vulnerabilities.Name, demoVulnerabilities(p)),
			policyreportingest.Name: ok(policyreportingest.Name, demoPolicyReports(p)),
			clusterinfo.Name:        ok(clusterinfo.Name, demoClusterInfo(p)),
			geo.Name:                ok(geo.Name, demoGeo(p)),
		}
		// One blind read keeps the demo honest about partial coverage: the metrics API is
		// forbidden on one edge cluster, so its utilization is unknown, not zero.
		if c.Name == "edge-lagos" {
			results[metrics.Name] = scanner.Result{
				Scanner: metrics.Name, State: scanner.StateErrored,
				Reason: "metrics.k8s.io API forbidden (RBAC)", Data: metrics.Data{},
			}
		}
		out[c.Name] = results
	}
	return out
}

// ok wraps data as a complete result of the named scanner.
func ok(name string, data any) scanner.Result {
	return scanner.Result{Scanner: name, Data: data}
}

// jitter returns a deterministic integer in [-spread, spread] for key, so distributions have
// real variance while staying stable across restarts.
func jitter(key string, spread int) int {
	if spread <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()%uint32(2*spread+1)) - spread
}

// itoa formats n in base 10.
func itoa(n int) string {
	return strconv.Itoa(n)
}

// nodeCount returns the cluster's node count. Production and development clusters vary in
// size; site and edge clusters are built to one footprint.
func (p demoProfile) nodeCount() int {
	switch p.C.Cohort {
	case "prod":
		return p.Shape.Nodes + jitter(p.C.Name+"nodes", 3)
	case "nonprod":
		return p.Shape.Nodes + jitter(p.C.Name+"nodes", 1)
	}
	return p.Shape.Nodes
}

// nodeNames returns the cluster's node names.
func (p demoProfile) nodeNames() []string {
	n := p.nodeCount()
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("%s-node-%02d", p.C.Name, i+1)
	}
	return out
}

// notReadyNodes returns how many nodes are NotReady at this scan: one on dev-eu-north-1 for four
// scans and one on edge-nyc-42 for two, both since recovered.
func (p demoProfile) notReadyNodes() int {
	switch {
	case p.C.Name == "edge-nyc-42" && p.between(6, 4):
		return 1
	case p.C.Name == "dev-eu-north-1" && p.between(14, 10):
		return 1
	}
	return 0
}

// memoryPressureNodes returns how many nodes report MemoryPressure: two on prod-us-east-1 over
// the last eight scans.
func (p demoProfile) memoryPressureNodes() int {
	if p.C.Name == "prod-us-east-1" && p.recent(8) {
		return 2
	}
	return 0
}

// utilization returns average CPU and memory percent at this scan. Members of a cohort sit at
// evenly spaced levels around the cohort's base, so no member stands out on a quiet day, and
// move a point or so from scan to scan.
func (p demoProfile) utilization() (cpu, mem float64) {
	k, n := p.cohortRank()
	spread := float64(k) - float64(n-1)/2
	cpu = p.Shape.CPU + 2*spread + float64(jitter(p.C.Name+"cpu"+itoa(p.I), 1))
	mem = p.Shape.Memory + 1.5*spread
	if n >= 7 {
		mem += float64(jitter(p.C.Name+"mem"+itoa(p.I), 1))
	}
	if p.C.Name == "prod-us-east-1" && p.recent(8) {
		mem += 12
	}
	return cpu, mem
}

// cohortRank returns the cluster's position within its cohort, in fleet table order, and the
// cohort's size.
func (p demoProfile) cohortRank() (k, n int) {
	for _, c := range demoFleet() {
		if c.Cohort != p.C.Cohort {
			continue
		}
		if c.Name == p.C.Name {
			k = n
		}
		n++
	}
	return k, n
}

// demoVersionData returns the version scanner's data.
func demoVersionData(p demoProfile) version.Data {
	parts := strings.Split(strings.TrimPrefix(p.C.Version, "v"), ".")
	return version.Data{Major: parts[0], Minor: parts[1], GitVersion: p.C.Version, Platform: "linux/amd64"}
}

// demoNodeHealth returns the node-health scanner's data.
func demoNodeHealth(p demoProfile) nodehealth.Data {
	names := p.nodeNames()
	notReady := p.notReadyNodes()
	pressure := p.memoryPressureNodes()
	d := nodehealth.Data{NodeCount: len(names)}
	for i, name := range names {
		nh := nodehealth.NodeHealth{Name: name, Ready: i >= notReady, MemoryPressure: i >= notReady && i < notReady+pressure}
		cond := func(typ string, bad bool, reason, msg string) nodehealth.NodeCondition {
			status := "False"
			if bad == (typ != "Ready") {
				status = "True"
			}
			return nodehealth.NodeCondition{Type: typ, Status: status, Reason: reason, Message: msg}
		}
		nh.Conditions = []nodehealth.NodeCondition{
			cond("MemoryPressure", nh.MemoryPressure, "KubeletHasInsufficientMemory", "kubelet has insufficient memory available"),
			cond("DiskPressure", false, "KubeletHasNoDiskPressure", "kubelet has no disk pressure"),
			cond("PIDPressure", false, "KubeletHasSufficientPID", "kubelet has sufficient PID available"),
			cond("Ready", nh.Ready, "KubeletReady", "kubelet is posting ready status"),
		}
		if !nh.Ready {
			nh.Conditions[3] = nodehealth.NodeCondition{Type: "Ready", Status: "Unknown", Reason: "NodeStatusUnknown", Message: "Kubelet stopped posting node status."}
			d.NotReadyNodes++
		}
		if nh.MemoryPressure {
			d.MemoryPressureNodes++
		}
		if nh.Ready && !nh.MemoryPressure {
			d.HealthyNodes++
		}
		d.Nodes = append(d.Nodes, nh)
	}
	d.UnhealthyNodes = d.NodeCount - d.HealthyNodes
	return d
}

// demoResources returns the resources scanner's data.
func demoResources(p demoProfile) resources.Data {
	names := p.nodeNames()
	notReady := p.notReadyNodes()
	d := resources.Data{NodeCount: len(names), ReadyNodes: len(names) - notReady}
	cpu, memGi := 8, 32
	if p.C.Cohort == "sites" || p.C.Cohort == "edge" {
		cpu, memGi = 4, 16
	}
	for i, name := range names {
		ready := "True"
		if i < notReady {
			ready = "Unknown"
		}
		d.Nodes = append(d.Nodes, resources.NodeInfo{
			Name: name, AllocatableCPU: itoa(cpu), AllocatableMemory: fmt.Sprintf("%dGi", memGi-1),
			CapacityCPU: itoa(cpu), CapacityMemory: fmt.Sprintf("%dGi", memGi),
			Conditions: map[string]string{"Ready": ready, "MemoryPressure": "False", "DiskPressure": "False", "PIDPressure": "False"},
		})
	}
	d.TotalAllocatableCPU = fmt.Sprintf("%dm", cpu*1000*len(names))
	d.TotalAllocatableMemory = fmt.Sprintf("%dGi", (memGi-1)*len(names))
	return d
}

// demoMetrics returns the metrics scanner's data.
func demoMetrics(p demoProfile) metrics.Data {
	cpu, mem := p.utilization()
	names := p.nodeNames()
	d := metrics.Data{
		Available: true, NodeCount: len(names), NodesWithUsage: len(names),
		AvgCPUPercent: new(cpu), AvgMemoryPercent: new(mem),
	}
	var maxCPU, maxMem float64
	for i, name := range names {
		offset := 1.5 * (float64(i) - float64(len(names)-1)/2)
		nc := min(cpu+offset, 99)
		nm := min(mem+offset, 99)
		if i < p.memoryPressureNodes() {
			nm = 97
		}
		d.Nodes = append(d.Nodes, metrics.NodeMetrics{
			Name: name, CPUPercent: nc, MemoryPercent: nm,
			CPUUsage: fmt.Sprintf("%dm", int(nc*80)), MemoryUsage: fmt.Sprintf("%dMi", int(nm*320)),
		})
		if nc > maxCPU {
			maxCPU, d.MaxCPUNode = nc, name
		}
		if nm > maxMem {
			maxMem, d.MaxMemoryNode = nm, name
		}
	}
	d.MaxCPUPercent, d.MaxMemoryPercent = new(maxCPU), new(maxMem)
	return d
}

// demoEvents returns the events scanner's data: a quiet baseline, OOM kills and evictions on
// prod-us-east-1 while it is under memory pressure, and a burst of probe failures on edge-nyc-42.
func demoEvents(p demoProfile) events.Data {
	type burst struct {
		reason, kind, ns, msg string
		count                 int
	}
	var bursts []burst
	if jitter(p.C.Name+"ev"+itoa(p.I), 4) == 4 {
		bursts = append(bursts, burst{"BackOff", "Pod", p.Shape.AppNamespaces[0], "Back-off restarting failed container", 2})
	}
	if p.memoryPressureNodes() > 0 {
		bursts = append(bursts,
			burst{"OOMKilling", "Node", "", "Memory cgroup out of memory: Killed process (java)", 46},
			burst{"Evicted", "Pod", "payments", "The node was low on resource: memory.", 38},
			burst{"FailedScheduling", "Pod", "checkout", "0/12 nodes are available: 2 Insufficient memory.", 21})
	}
	if p.notReadyNodes() > 0 {
		bursts = append(bursts, burst{"NodeNotReady", "Node", "", "Node is not ready", 6})
	}
	d := events.Data{WindowSeconds: 3600}
	for i, b := range bursts {
		d.WarningEvents += b.count
		d.TopWarningReasons = append(d.TopWarningReasons, events.ReasonSummary{Reason: b.reason, Count: int32(b.count), EventCount: b.count})
		seen := p.At.Add(-time.Duration(i*7) * time.Minute).Format(time.RFC3339)
		d.RecentWarnings = append(d.RecentWarnings, events.EventInfo{
			Namespace: b.ns, InvolvedObject: fmt.Sprintf("%s-%s-%d", b.ns, strings.ToLower(b.kind), i), Kind: b.kind,
			Reason: b.reason, Message: b.msg, Type: "Warning", Count: int32(b.count), FirstSeen: seen, LastSeen: seen,
		})
	}
	return d
}

// namespaces returns every namespace of the cluster.
func (p demoProfile) namespaces() []string {
	return append(append([]string{}, demoSystemNamespaces...), p.Shape.AppNamespaces...)
}

// demoNamespaces returns the namespace scanner's data.
func demoNamespaces(p demoProfile) namespace.Data {
	names := p.namespaces()
	labels := make(map[string]map[string]string, len(names))
	for _, ns := range names {
		labels[ns] = map[string]string{"kubernetes.io/metadata.name": ns}
	}
	return namespace.Data{Count: len(names), Names: names, Labels: labels}
}

// demoSecurity returns the Pod Security scanner's data: application namespaces enforced, the
// system namespaces as privileged, which enforces nothing and so counts as unenforced, and one
// namespace on dev-canadacentral left unlabeled for eight scans until someone labeled it.
func demoSecurity(p demoProfile) security.Data {
	d := security.Data{LevelDistribution: map[string]int{}}
	for _, ns := range p.namespaces() {
		level := "baseline"
		switch ns {
		case "kube-system":
			level = "privileged"
		case "payments", "accounts", "auth", "pos":
			level = "restricted"
		}
		if p.C.Name == "dev-canadacentral" && ns == "sandbox" && p.between(14, 6) {
			d.Namespaces = append(d.Namespaces, security.NamespaceSecurity{Namespace: ns})
			d.UnenforcedCount++
			d.LevelDistribution["none"]++
			continue
		}
		d.Namespaces = append(d.Namespaces, security.NamespaceSecurity{Namespace: ns, Enforce: level, EnforceVersion: "latest"})
		if security.Enforced(level) {
			d.EnforcedCount++
		} else {
			d.UnenforcedCount++
		}
		d.LevelDistribution[level]++
	}
	d.NamespaceCount = len(d.Namespaces)
	return d
}

// demoNetworkPolicies returns the network policy scanner's data: a default-deny policy in every
// application namespace, except two namespaces on site-sao-paulo-1 that went without for the
// first half of the series.
func demoNetworkPolicies(p demoProfile) networkpolicy.Data {
	var d networkpolicy.Data
	for _, ns := range p.namespaces() {
		if ns == "kube-node-lease" || ns == "kube-public" {
			d.NamespacesWithPolicies++
			continue
		}
		if p.C.Name == "site-sao-paulo-1" && (ns == "sensors" || ns == "local-cache") && p.between(22, 12) {
			d.NamespacesWithoutPolicies++
			continue
		}
		d.NamespacesWithPolicies++
		d.Policies = append(d.Policies,
			networkpolicy.PolicyInfo{Namespace: ns, Name: "default-deny", PolicyTypes: []string{"Ingress", "Egress"}},
			networkpolicy.PolicyInfo{Namespace: ns, Name: "allow-same-namespace", PolicyTypes: []string{"Ingress"}, IngressRuleCount: 1})
	}
	d.Count = len(d.Policies)
	return d
}

// demoQuotas returns the resource quota scanner's data: a quota and a limit range in every
// application namespace.
func demoQuotas(p demoProfile) quota.Data {
	var d quota.Data
	for _, ns := range p.Shape.AppNamespaces {
		d.Quotas = append(d.Quotas, quota.Info{
			Namespace: ns, Name: "compute",
			Hard: map[string]string{"requests.cpu": "8", "requests.memory": "16Gi"},
			Used: map[string]string{"requests.cpu": "3", "requests.memory": "7Gi"},
		})
		d.LimitRanges = append(d.LimitRanges, quota.LimitRangeInfo{Namespace: ns, Name: "defaults", ItemCount: 2})
	}
	d.QuotaCount, d.LimitRangeCount, d.NamespacesWithQuotas = len(d.Quotas), len(d.LimitRanges), len(d.Quotas)
	return d
}

// demoServices returns the service scanner's data: an api and a web service per application
// namespace, plus the cluster's own.
func demoServices(p demoProfile) service.Data {
	d := service.Data{Services: []service.Info{
		{Namespace: "default", Name: "kubernetes", Type: "ClusterIP", Ports: []service.PortInfo{{Name: "https", Port: 443, Protocol: "TCP"}}},
		{Namespace: "kube-system", Name: "kube-dns", Type: "ClusterIP", Ports: []service.PortInfo{{Name: "dns", Port: 53, Protocol: "UDP"}}},
	}}
	for _, ns := range p.Shape.AppNamespaces {
		d.Services = append(d.Services,
			service.Info{Namespace: ns, Name: "api", Type: "ClusterIP", Ports: []service.PortInfo{{Name: "http", Port: 8080, Protocol: "TCP"}}},
			service.Info{Namespace: ns, Name: "web", Type: "ClusterIP", Ports: []service.PortInfo{{Name: "http", Port: 80, Protocol: "TCP"}}})
	}
	d.Count = len(d.Services)
	return d
}

// demoIngresses returns the ingress scanner's data.
func demoIngresses(p demoProfile) ingress.Data {
	var d ingress.Data
	for i := range p.Shape.Ingresses {
		ns := p.Shape.AppNamespaces[i%len(p.Shape.AppNamespaces)]
		d.Ingresses = append(d.Ingresses, ingress.Info{
			Namespace: ns, Name: fmt.Sprintf("%s-%d", ns, i/len(p.Shape.AppNamespaces)), IngressClassName: "nginx",
			Hosts: []string{fmt.Sprintf("%s.%s.example.internal", ns, p.C.Name)}, TLS: true,
		})
	}
	d.Count = len(d.Ingresses)
	return d
}

// demoCRDs returns the CRD scanner's data: three kinds per installed API group.
func demoCRDs(p demoProfile) crd.Data {
	var d crd.Data
	for _, g := range p.Shape.CRDGroups {
		prefix := strings.Split(g, ".")[0]
		for _, kind := range []string{"configs", "policies", "statuses"} {
			d.CRDs = append(d.CRDs, crd.Info{Name: prefix + kind + "." + g, Group: g, Versions: []string{"v1"}, Scope: "Namespaced"})
		}
	}
	d.Count = len(d.CRDs)
	return d
}

// demoRBAC returns the RBAC scanner's data. prod-us-west-2 gains sixty ClusterRoles a third of the
// way from the end of the series, a sprawl the drift ledger shows arriving.
func demoRBAC(p demoProfile) rbac.Data {
	clusterRoles := p.Shape.ClusterRoles + jitter(p.C.Name+"cr", 3)
	if p.C.Name == demoStepCluster && p.I >= p.N-p.N/3 {
		clusterRoles += 60
	}
	d := rbac.Data{ClusterRoleCount: clusterRoles, ClusterRoleBindingCount: clusterRoles - 8}
	for i := range clusterRoles {
		d.Roles = append(d.Roles, rbac.RoleInfo{Kind: "ClusterRole", Name: fmt.Sprintf("role-%03d", i), RuleCount: 3 + i%7})
	}
	for _, ns := range p.Shape.AppNamespaces {
		d.Roles = append(d.Roles, rbac.RoleInfo{Kind: "Role", Namespace: ns, Name: "deployer", RuleCount: 4})
		d.Bindings = append(d.Bindings, rbac.BindingInfo{Kind: "RoleBinding", Namespace: ns, Name: "deployer", RoleRef: "deployer", SubjectCount: 1})
	}
	d.RoleCount, d.RoleBindingCount = len(p.Shape.AppNamespaces), len(p.Shape.AppNamespaces)
	return d
}

// demoRBACAudit returns the RBAC audit scanner's data: no risky bindings anywhere.
func demoRBACAudit(p demoProfile) rbacaudit.Data {
	return rbacaudit.Data{RoleBindingsAudited: len(p.Shape.AppNamespaces), RiskBindings: []rbacaudit.RiskBinding{}}
}

// pods returns the pod count, about four per application namespace.
func (p demoProfile) pods() int {
	return 4*len(p.Shape.AppNamespaces) + 6 + jitter(p.C.Name+"pods", 3)
}

// demoWorkloadSecurity returns the workload security scanner's data: hardened pods, except a
// privileged relay container on edge-nyc-42 for eight scans in the middle of the series.
func demoWorkloadSecurity(p demoProfile) workloadsec.Data {
	d := workloadsec.Data{TotalPods: p.pods(), HighRiskPods: []workloadsec.PodRisk{}}
	d.BaselineContainers = p.pods()
	d.RunAsNonRootContainers = d.BaselineContainers
	if p.C.Name == "edge-nyc-42" && p.between(16, 8) {
		d.PrivilegedContainers = 1
		d.AllowPrivilegeEscalation = 1
		d.HighRiskPods = append(d.HighRiskPods, workloadsec.PodRisk{Namespace: "relay", Pod: "relay-agent-7c9f4", Container: "agent", Risks: []string{"privileged", "allow-privilege-escalation"}})
	}
	return d
}

// demoImageAudit returns the image audit scanner's data: digest-pinned images, except two
// containers on staging-ap-southeast-1 that tracked :latest for a stretch of the series.
func demoImageAudit(p demoProfile) imageaudit.Data {
	containers := p.pods()
	d := imageaudit.Data{TotalContainers: containers, UniqueImages: containers / 2, ImageRisks: []imageaudit.ImageRisk{}}
	if p.C.Name == "staging-ap-southeast-1" && p.between(18, 10) {
		d.LatestTag, d.NoDigest = 2, 2
		for _, ns := range []string{"sandbox", "ci-runners"} {
			d.ImageRisks = append(d.ImageRisks, imageaudit.ImageRisk{Namespace: ns, Pod: ns + "-runner-0", Container: "runner", Image: "registry.example.internal/" + ns + ":latest", Risks: []string{"latest-tag", "no-digest-pin"}})
		}
	}
	return d
}

// demoCerts returns the certificate scanner's data. Ingress certificates renew well ahead,
// except one on site-osaka-1 that is running out, and one on site-paris-12 that ran close before
// it was renewed.
func demoCerts(p demoProfile) certs.Data {
	expiries := []time.Time{p.Latest.Add(75 * 24 * time.Hour), p.Latest.Add(140 * 24 * time.Hour)}
	switch {
	case p.C.Name == "site-osaka-1":
		expiries = append(expiries, p.Latest.Add(12*24*time.Hour))
	case p.C.Name == "site-paris-12" && p.I < p.N-10:
		expiries = append(expiries, p.Latest.Add(-48*time.Hour))
	}
	d := certs.Data{Soonest: -1}
	for i, exp := range expiries {
		days := int(exp.Sub(p.At).Hours() / 24)
		d.Certs = append(d.Certs, certs.Cert{Name: fmt.Sprintf("ingress-tls-%d", i), Namespace: p.Shape.AppNamespaces[i%len(p.Shape.AppNamespaces)], Kind: "Secret", Subject: "CN=" + p.C.Name + ".example.internal", NotAfter: exp, DaysRemaining: days})
		switch {
		case days < 7:
			d.Critical++
		case days < 30:
			d.Warning++
		default:
			d.Info++
		}
		if d.Soonest < 0 || days < d.Soonest {
			d.Soonest = days
		}
	}
	d.TotalCerts = len(d.Certs)
	return d
}

// demoDeprecated returns the deprecated API scanner's data: prod-eu-central-1 still serves a
// policy/v1beta1 PodDisruptionBudget.
func demoDeprecated(p demoProfile) deprecatedapis.Data {
	d := deprecatedapis.Data{ServerVersion: p.C.Version, Deprecated: []deprecatedapis.Deprecated{}}
	if p.C.Name == "prod-eu-central-1" {
		d.Deprecated = append(d.Deprecated, deprecatedapis.Deprecated{APIVersion: "policy/v1beta1", Kind: "PodDisruptionBudget", Replacement: "policy/v1", RemovedIn: "1.25", InstanceCount: 3})
		d.TotalInstances = 3
	}
	return d
}

// demoCoverage returns the workload coverage scanner's data: every replicated workload has a
// PodDisruptionBudget and an autoscaler, except two on site-london-8 until they got budgets.
func demoCoverage(p demoProfile) workloadcoverage.Data {
	d := workloadcoverage.Data{TotalReplicated: len(p.Shape.AppNamespaces), Gaps: []workloadcoverage.Coverage{}}
	if p.C.Name == "site-london-8" && p.between(12, 3) {
		for _, ns := range []string{"kiosk", "sync"} {
			d.Gaps = append(d.Gaps, workloadcoverage.Coverage{Kind: "Deployment", Namespace: ns, Name: ns, Replicas: 2, HasHPA: true})
		}
		d.MissingPDB = 2
	}
	return d
}

// demoAdmission returns the admission webhook scanner's data: a policy webhook everywhere, which
// on site-osaka-1 lost its endpoints for three scans early in the series.
func demoAdmission(p demoProfile) admission.Data {
	healthy := !(p.C.Name == "site-osaka-1" && p.between(20, 17))
	notAfter := p.Latest.Add(300 * 24 * time.Hour)
	d := admission.Data{TotalWebhooks: 1, Webhooks: []admission.Webhook{{
		Configuration: "policy-engine", Webhook: "validate.policy-engine.io", Type: "Validating",
		Service: "policy-engine/webhook", EndpointsHealthy: healthy, FailurePolicy: "Ignore",
		CABundleNotAfter: notAfter, CABundleDaysRemaining: int(notAfter.Sub(p.At).Hours() / 24),
	}}}
	if !healthy {
		d.UnhealthyWebhooks = 1
	}
	return d
}

// demoVulnerabilities returns the vulnerability report scanner's data: high and medium findings
// spread across the fleet, no criticals.
func demoVulnerabilities(p demoProfile) vulnerabilities.Data {
	high := 6 + jitter(p.C.Name+"high", 3)
	return vulnerabilities.Data{
		Available: true, Reports: p.pods() / 2, High: high, Medium: 22 + jitter(p.C.Name+"med", 6), Low: 40 + jitter(p.C.Name+"low", 10),
		TopImages: []vulnerabilities.VulnerableImage{{Namespace: p.Shape.AppNamespaces[0], Workload: "api", Image: "registry.example.internal/api:2.14.1", High: high}},
	}
}

// demoPolicyReports returns the policy report scanner's data.
func demoPolicyReports(p demoProfile) policyreportingest.Data {
	return policyreportingest.Data{Available: true, Reports: len(p.Shape.AppNamespaces), TopFailures: []policyreportingest.PolicyFailure{}}
}

// demoClusterInfo returns the cluster info scanner's data: one OS image, kernel, and runtime per
// cluster.
func demoClusterInfo(p demoProfile) clusterinfo.Data {
	names := p.nodeNames()
	d := clusterinfo.Data{
		NodeCount: len(names), OSImages: []string{"Ubuntu 22.04.5 LTS"}, KernelVersions: []string{"6.8.0-1021"},
		RuntimeVersions: []string{"containerd://1.7.24"}, KubeletVersions: []string{p.C.Version},
	}
	for _, n := range names {
		d.Nodes = append(d.Nodes, clusterinfo.NodeInfo{Name: n, OSImage: d.OSImages[0], KernelVersion: d.KernelVersions[0], ContainerRuntimeVersion: d.RuntimeVersions[0], KubeletVersion: p.C.Version})
	}
	return d
}

// demoGeo returns the geo scanner's data: a cloud region for auto-placed clusters, the site label
// for configmap and annotation placements, and nothing for clusters placed by a stored override.
func demoGeo(p demoProfile) geo.Data {
	d := geo.Data{NodeCount: p.nodeCount()}
	switch p.C.Source {
	case "auto":
		d.HasLocation, d.Source = true, "auto"
		d.Provider, d.Region, d.City, d.Lat, d.Lng = p.C.Provider, p.C.Region, p.C.City, p.C.Lat, p.C.Lng
		d.Regions, d.LocatedNodes = []string{p.C.Region}, d.NodeCount
	case "configmap", "annotation":
		d.HasLocation, d.Source = true, p.C.Source
		d.Site, d.City, d.Lat, d.Lng = p.C.Site, p.C.Site, p.C.Lat, p.C.Lng
	}
	return d
}
