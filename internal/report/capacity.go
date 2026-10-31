package report

import (
	"fmt"
	"math"
	"sort"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Capacity status values assigned by analyzeCapacity.
const (
	capacityCritical = "critical"
	capacityStrained = "strained"
	capacityBusy     = "busy"
	capacityHealthy  = "healthy"
	// capacityUnknown marks a cluster whose utilization no scanner observed and whose other
	// signals show no strain, so neither healthy nor busy can be claimed.
	capacityUnknown = "unknown"
)

// CapacityAnalysis holds smart analysis for a single cluster, correlating
// multiple signals rather than applying naive thresholds.
type CapacityAnalysis struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// CPUUtilization is the average CPU percentage, nil when no scanner observed it.
	CPUUtilization *float64 `json:"cpu_utilization,omitempty"`
	// MemoryUtilization is the average memory percentage, nil when no scanner observed it.
	MemoryUtilization *float64 `json:"memory_utilization,omitempty"`
	// HasMemoryPressure is true when any node reports MemoryPressure=True.
	HasMemoryPressure bool `json:"has_memory_pressure"`
	// HasDiskPressure is true when any node reports DiskPressure=True.
	HasDiskPressure bool `json:"has_disk_pressure"`
	// HasOOMEvents is true when OOMKilling events were detected.
	HasOOMEvents bool `json:"has_oom_events"`
	// HasSchedulingFailures is true when FailedScheduling events were detected.
	HasSchedulingFailures bool `json:"has_scheduling_failures"`
	// NodeCount is the total number of nodes.
	NodeCount int `json:"node_count"`
	// HealthyNodes is the number of healthy nodes.
	HealthyNodes int `json:"healthy_nodes"`
	// HeadroomCPU is the percentage of CPU capacity still available, nil when unobserved.
	HeadroomCPU *float64 `json:"headroom_cpu,omitempty"`
	// HeadroomMemory is the percentage of memory capacity still available, nil when unobserved.
	HeadroomMemory *float64 `json:"headroom_memory,omitempty"`
	// Status is the assessed state: healthy, busy, strained, critical, or unknown.
	Status string `json:"status"`
	// Recommendation is a plain English capacity recommendation.
	Recommendation string `json:"recommendation,omitempty"`
	// NodesNeededForTarget is how many additional nodes would bring memory below 70%.
	NodesNeededForTarget int `json:"nodes_needed_for_target,omitempty"`
	// GroupDeviation describes how this cluster compares to its group peers.
	GroupDeviation string `json:"group_deviation,omitempty"`
}

// clusterSignals holds extracted signals for capacity analysis.
type clusterSignals struct {
	// utilObs is how far cpuPct and memPct can be trusted. Unobserved means both are zero
	// placeholders that must never be read as a measurement.
	utilObs observation
	// utilGap names the read that left utilization unobserved, empty when it was observed.
	utilGap string
	// cpuPct is the average CPU utilization percent.
	cpuPct float64
	// memPct is the average memory utilization percent.
	memPct float64
	// nodeCount is the number of nodes.
	nodeCount int
	// healthyNodes is the number of Ready nodes without pressure.
	healthyNodes int
	// memPressure is the number of nodes reporting MemoryPressure.
	memPressure int
	// diskPressure is the number of nodes reporting DiskPressure.
	diskPressure int
	// notReady is the number of NotReady nodes.
	notReady int
	// oomEvents is true when recent warnings include OOM kills.
	oomEvents bool
	// schedFail is true when recent warnings include FailedScheduling.
	schedFail bool
}

// analyzeCapacity runs smart capacity analysis across all clusters in a report.
// Groups can be nil when no grouping is available.
func analyzeCapacity(r *Report, groups map[string][]string) []CapacityAnalysis {
	signals := extractAllSignals(r)
	var analyzes []CapacityAnalysis

	// Build group membership lookup: cluster -> group names.
	clusterGroups := make(map[string][]string)
	if groups != nil {
		for gName, members := range groups {
			for _, c := range members {
				clusterGroups[c] = append(clusterGroups[c], gName)
			}
		}
	}

	for _, cluster := range r.Clusters {
		sig, ok := signals[cluster]
		if !ok {
			continue
		}

		ca := CapacityAnalysis{
			Cluster:               cluster,
			HasMemoryPressure:     sig.memPressure > 0,
			HasDiskPressure:       sig.diskPressure > 0,
			HasOOMEvents:          sig.oomEvents,
			HasSchedulingFailures: sig.schedFail,
			NodeCount:             sig.nodeCount,
			HealthyNodes:          sig.healthyNodes,
		}
		if sig.utilObs.seen() {
			ca.CPUUtilization = new(sig.cpuPct)
			ca.MemoryUtilization = new(sig.memPct)
			ca.HeadroomCPU = new(100 - sig.cpuPct)
			ca.HeadroomMemory = new(100 - sig.memPct)
		}

		ca.Status = assessStatus(sig)
		ca.Recommendation = recommend(sig, ca.Status) + sig.utilObs.note()
		ca.NodesNeededForTarget = nodesNeeded(sig, 70.0)

		// Compare to group peers.
		for _, gName := range clusterGroups[cluster] {
			if groups == nil {
				continue
			}
			peers := groups[gName]
			if len(peers) < 2 {
				continue
			}
			ca.GroupDeviation = groupComparison(cluster, gName, peers, signals)
			break
		}

		analyzes = append(analyzes, ca)
	}

	sort.Slice(analyzes, func(i, j int) bool {
		order := map[string]int{
			capacityCritical: 0, capacityStrained: 1, capacityBusy: 2, capacityUnknown: 3,
			capacityHealthy: 4,
		}
		return order[analyzes[i].Status] < order[analyzes[j].Status]
	})

	return analyzes
}

// assessStatus determines cluster state by correlating signals, not just reading utilization
// numbers. Pressure and failure events still mark a cluster strained or critical without a
// utilization reading, but healthy and busy rest on utilization, so without one the status is
// unknown.
func assessStatus(sig clusterSignals) string {
	seen := sig.utilObs.seen()
	hasPressure := sig.memPressure > 0 || sig.diskPressure > 0
	hasFailures := sig.oomEvents || sig.schedFail
	highUtil := seen && (sig.memPct > 85 || sig.cpuPct > 85)
	elevatedUtil := seen && (sig.memPct > 70 || sig.cpuPct > 70)

	// Critical: pressure + failures, or nodes down + high utilization.
	if hasPressure && hasFailures {
		return capacityCritical
	}
	if sig.notReady > 0 && highUtil {
		return capacityCritical
	}
	if hasPressure && highUtil {
		return capacityCritical
	}

	// Strained: pressure or failures without both, or very high utilization.
	if hasPressure || hasFailures {
		return capacityStrained
	}
	if highUtil {
		return capacityStrained
	}

	// Busy: elevated utilization but no pressure signals. Working hard but healthy.
	if elevatedUtil {
		return capacityBusy
	}
	if !seen {
		return capacityUnknown
	}
	return capacityHealthy
}

// recommend generates a capacity recommendation based on correlated signals. It states a
// utilization figure only when one was observed.
func recommend(sig clusterSignals, status string) string {
	switch status {
	case capacityUnknown:
		return "Utilization is unknown: " + sig.utilGap
	case capacityCritical:
		needed := nodesNeeded(sig, 70.0)
		if sig.oomEvents && sig.memPressure > 0 && needed == 0 {
			return fmt.Sprintf(
				"Cluster is actively OOM-killing pods with %d node(s) under memory pressure%s. "+
					"The load is uneven: set memory limits and rebalance the workloads on those nodes.",
				sig.memPressure, memClause(sig))
		}
		if sig.oomEvents && sig.memPressure > 0 {
			return fmt.Sprintf(
				"Cluster is actively OOM-killing pods with %d node(s) under memory pressure. "+
					"Add %d node(s) to bring memory below 70%% or increase per-node memory.",
				sig.memPressure, needed)
		}
		if sig.memPressure > 0 && needed == 0 {
			return fmt.Sprintf(
				"%d of %d nodes report MemoryPressure%s. "+
					"The load is uneven: rebalance or evict low-priority workloads on those nodes.",
				sig.memPressure, sig.nodeCount, memClause(sig))
		}
		if sig.memPressure > 0 {
			return fmt.Sprintf(
				"%d of %d nodes report MemoryPressure. Add %d node(s) to relieve pressure or evict low-priority workloads.",
				sig.memPressure, sig.nodeCount, needed)
		}
		if sig.notReady > 0 && !sig.utilObs.seen() {
			return fmt.Sprintf(
				"%d node(s) are not Ready. Investigate node conditions before scaling.", sig.notReady)
		}
		if sig.notReady > 0 {
			return fmt.Sprintf(
				"%d node(s) are not Ready. Investigate node conditions before scaling. Remaining nodes are overloaded at %.0f%% memory.",
				sig.notReady, sig.memPct)
		}
		if needed == 0 {
			return "Resource exhaustion detected. Check node conditions and events before scaling."
		}
		return fmt.Sprintf("Resource exhaustion detected. Add %d node(s) to bring utilization below 70%%.", needed)

	case capacityStrained:
		needed := nodesNeeded(sig, 70.0)
		if sig.schedFail && needed == 0 {
			return fmt.Sprintf(
				"FailedScheduling events show pods that do not fit%s. "+
					"Check pod requests, node selectors, taints, and affinity before adding nodes.",
				memClause(sig))
		}
		if sig.schedFail {
			return fmt.Sprintf(
				"FailedScheduling events indicate insufficient capacity. Add %d node(s) or reduce workload resource requests.",
				needed)
		}
		if !sig.utilObs.seen() {
			return "Nodes report pressure or failure events, but utilization is unknown: " + sig.utilGap
		}
		if sig.memPct > 85 {
			return fmt.Sprintf(
				"Memory at %.0f%% with no pressure yet, but little headroom remains. Consider adding %d node(s) proactively.",
				sig.memPct, needed)
		}
		if needed == 0 {
			return fmt.Sprintf("Utilization is elevated (CPU %.0f%%, memory %.0f%%). Monitor closely.", sig.cpuPct, sig.memPct)
		}
		return fmt.Sprintf(
			"Utilization is elevated (CPU %.0f%%, memory %.0f%%). Monitor closely. %d additional node(s) would bring usage below 70%%.",
			sig.cpuPct, sig.memPct, needed)

	case capacityBusy:
		return fmt.Sprintf(
			"Cluster is running at CPU %.0f%%, memory %.0f%% with no pressure conditions. "+
				"This is healthy but has limited headroom (%.0f%% memory free). "+
				"If traffic is expected to grow, consider adding capacity proactively.",
			sig.cpuPct, sig.memPct, 100-sig.memPct)

	default:
		return fmt.Sprintf(
			"Cluster is healthy with %.0f%% CPU and %.0f%% memory headroom.",
			100-sig.cpuPct, 100-sig.memPct)
	}
}

// pctText formats a utilization percentage as a whole number, or "unknown" when it was not
// observed.
func pctText(p *float64) string {
	if p == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.0f%%", *p)
}

// memClause returns " while average memory is N%" for a cluster with an observed memory
// reading, or nothing when utilization was not observed.
func memClause(sig clusterSignals) string {
	if !sig.utilObs.seen() {
		return ""
	}
	return fmt.Sprintf(" while average memory is %.0f%%", sig.memPct)
}

// nodesNeeded calculates how many additional nodes are required to bring
// memory utilization below the target percentage, assuming each new node
// adds the same capacity as existing nodes. Without an observed utilization it
// returns 0, since no count can be derived from an unknown.
func nodesNeeded(sig clusterSignals, targetPct float64) int {
	if !sig.utilObs.seen() || sig.nodeCount == 0 || sig.memPct <= targetPct {
		return 0
	}
	// Total memory units currently used = memPct/100 * nodeCount.
	usedUnits := sig.memPct / 100 * float64(sig.nodeCount)
	// Need: usedUnits / totalNodes <= targetPct/100.
	// totalNodes >= usedUnits / (targetPct/100).
	needed := usedUnits / (targetPct / 100)
	additional := max(int(math.Ceil(needed))-sig.nodeCount, 1)
	return additional
}

// groupComparison compares a cluster to the median of its group peers the metrics scanner read
// and describes the deviation. A cluster without a metrics reading is not compared, and a peer
// without one is left out, so an unknown never counts as zero utilization.
func groupComparison(cluster, groupName string, peers []string, signals map[string]clusterSignals) string {
	sig := signals[cluster]
	if !sig.utilObs.seen() {
		return ""
	}
	var peerMem []float64
	var peerCPU []float64
	for _, p := range peers {
		if p == cluster {
			continue
		}
		if s, ok := signals[p]; ok && s.utilObs.seen() {
			peerMem = append(peerMem, s.memPct)
			peerCPU = append(peerCPU, s.cpuPct)
		}
	}
	if len(peerMem) == 0 {
		return ""
	}

	peerMem50 := util.Median(peerMem)
	peerCPU50 := util.Median(peerCPU)

	memDiff := sig.memPct - peerMem50
	cpuDiff := sig.cpuPct - peerCPU50

	// Only report if the deviation is significant (>10 percentage points).
	if math.Abs(memDiff) < 10 && math.Abs(cpuDiff) < 10 {
		return fmt.Sprintf("Within normal range for group %q (peer median: CPU %.0f%%, memory %.0f%%).", groupName, peerCPU50, peerMem50)
	}

	parts := ""
	if math.Abs(memDiff) >= 10 {
		dir := "higher"
		if memDiff < 0 {
			dir = "lower"
		}
		parts += fmt.Sprintf("Memory is %.0f%% points %s than the group %q median (%.0f%% vs %.0f%%). ", math.Abs(memDiff), dir, groupName, sig.memPct, peerMem50)
	}
	if math.Abs(cpuDiff) >= 10 {
		dir := "higher"
		if cpuDiff < 0 {
			dir = "lower"
		}
		parts += fmt.Sprintf("CPU is %.0f%% points %s than the group %q median (%.0f%% vs %.0f%%).", math.Abs(cpuDiff), dir, groupName, sig.cpuPct, peerCPU50)
	}
	return parts
}

// extractAllSignals pulls capacity-relevant data from the report for all clusters. Every
// cluster gets an entry. Utilization carries its observation, and a cluster without one names
// the read that failed. Node and event counts are presence signals, so an unobserved count
// stands as no evidence of pressure.
func extractAllSignals(r *Report) map[string]clusterSignals {
	out := make(map[string]clusterSignals, len(r.Clusters))
	for _, cluster := range r.Clusters {
		var sig clusterSignals
		var cpuObs, memObs observation
		sig.cpuPct, cpuObs = observe(r, "metrics", cluster, "avg_cpu_percent")
		sig.memPct, memObs = observe(r, "metrics", cluster, "avg_memory_percent")
		sig.utilObs = weakest(cpuObs, memObs)
		if !sig.utilObs.seen() {
			sig.cpuPct, sig.memPct = 0, 0
			sig.utilGap = utilizationGap(r, cluster)
		}
		sig.nodeCount, _ = observeInt(r, "node-health", cluster, "node_count")
		sig.healthyNodes, _ = observeInt(r, "node-health", cluster, "healthy_nodes")
		sig.memPressure, _ = observeInt(r, "node-health", cluster, "memory_pressure_nodes")
		sig.diskPressure, _ = observeInt(r, "node-health", cluster, "disk_pressure_nodes")
		sig.notReady, _ = observeInt(r, "node-health", cluster, "not_ready_nodes")
		sig.oomEvents = hasEventReason(r, cluster, "OOMKilling")
		sig.schedFail = hasEventReason(r, cluster, "FailedScheduling")
		out[cluster] = sig
	}
	return out
}

// utilizationGap names the metrics read that left a cluster's utilization unobserved.
func utilizationGap(r *Report, cluster string) string {
	st, ok := runState(r, "metrics", cluster)
	switch {
	case !ok:
		return "the metrics scanner did not run on this cluster, so headroom cannot be assessed."
	case st == scanner.StateErrored:
		return "the node metrics read failed, so headroom cannot be assessed. " +
			"Check that the scanner can list nodes in metrics.k8s.io."
	case st == scanner.StateUnavailable:
		return "the cluster does not serve the metrics.k8s.io API. " +
			"Install metrics-server to measure headroom."
	}
	return "no node's usage resolved to a percentage of its allocatable capacity, " +
		"so headroom cannot be assessed. Check that the scanner can list nodes."
}

// hasEventReason reports whether a cluster's warning events include reason. An unobserved
// events run is no evidence either way and reports false.
func hasEventReason(r *Report, cluster, reason string) bool {
	m, obs := clusterView(r, "events", cluster)
	if !obs.seen() {
		return false
	}
	reasons, ok := m["top_warning_reasons"].([]any)
	if !ok {
		return false
	}
	for _, item := range reasons {
		if rm, ok := item.(map[string]any); ok {
			if r, ok := rm["reason"].(string); ok && r == reason {
				return true
			}
		}
	}
	return false
}
