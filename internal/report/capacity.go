package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// CapacityAnalysis holds smart analysis for a single cluster, correlating
// multiple signals rather than applying naive thresholds.
type CapacityAnalysis struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// CPUUtilization is the average CPU percentage.
	CPUUtilization float64 `json:"cpu_utilization"`
	// MemoryUtilization is the average memory percentage.
	MemoryUtilization float64 `json:"memory_utilization"`
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
	// HeadroomCPU is the percentage of CPU capacity still available.
	HeadroomCPU float64 `json:"headroom_cpu"`
	// HeadroomMemory is the percentage of memory capacity still available.
	HeadroomMemory float64 `json:"headroom_memory"`
	// Status is the assessed state: healthy, busy, strained, critical.
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
	cpuPct       float64
	memPct       float64
	maxMemPct    float64
	nodeCount    int
	healthyNodes int
	memPressure  int
	diskPressure int
	notReady     int
	oomEvents    bool
	schedFail    bool
	warnEvents   int
}

// AnalyzeCapacity runs smart capacity analysis across all clusters in a report.
// Groups can be nil when no grouping is available.
func AnalyzeCapacity(r *Report, groups map[string][]string) []CapacityAnalysis {
	signals := extractAllSignals(r)
	var analyses []CapacityAnalysis

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
			Cluster:           cluster,
			CPUUtilization:    sig.cpuPct,
			MemoryUtilization: sig.memPct,
			HasMemoryPressure: sig.memPressure > 0,
			HasDiskPressure:   sig.diskPressure > 0,
			HasOOMEvents:      sig.oomEvents,
			HasSchedulingFailures: sig.schedFail,
			NodeCount:         sig.nodeCount,
			HealthyNodes:      sig.healthyNodes,
			HeadroomCPU:       100 - sig.cpuPct,
			HeadroomMemory:    100 - sig.memPct,
		}

		ca.Status = assessStatus(sig)
		ca.Recommendation = recommend(sig, ca.Status)
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

		analyses = append(analyses, ca)
	}

	sort.Slice(analyses, func(i, j int) bool {
		order := map[string]int{"critical": 0, "strained": 1, "busy": 2, "healthy": 3}
		return order[analyses[i].Status] < order[analyses[j].Status]
	})

	return analyses
}

// assessStatus determines cluster state by correlating signals, not just
// reading utilization numbers.
func assessStatus(sig clusterSignals) string {
	hasPressure := sig.memPressure > 0 || sig.diskPressure > 0
	hasFailures := sig.oomEvents || sig.schedFail
	highUtil := sig.memPct > 85 || sig.cpuPct > 85
	elevatedUtil := sig.memPct > 70 || sig.cpuPct > 70

	// Critical: pressure + failures, or nodes down + high utilization.
	if hasPressure && hasFailures {
		return "critical"
	}
	if sig.notReady > 0 && highUtil {
		return "critical"
	}
	if hasPressure && highUtil {
		return "critical"
	}

	// Strained: pressure or failures without both, or very high utilization.
	if hasPressure || hasFailures {
		return "strained"
	}
	if highUtil {
		return "strained"
	}

	// Busy: elevated utilization but no pressure signals. Working hard but healthy.
	if elevatedUtil {
		return "busy"
	}

	return "healthy"
}

// recommend generates a capacity recommendation based on correlated signals.
func recommend(sig clusterSignals, status string) string {
	switch status {
	case "critical":
		needed := nodesNeeded(sig, 70.0)
		if sig.oomEvents && sig.memPressure > 0 {
			return fmt.Sprintf(
				"Cluster is actively OOM-killing pods with %d node(s) under memory pressure. "+
					"Add %d node(s) to bring memory below 70%% or increase per-node memory.",
				sig.memPressure, needed)
		}
		if sig.memPressure > 0 {
			return fmt.Sprintf(
				"%d of %d nodes report MemoryPressure. Add %d node(s) to relieve pressure or evict low-priority workloads.",
				sig.memPressure, sig.nodeCount, needed)
		}
		if sig.notReady > 0 {
			return fmt.Sprintf(
				"%d node(s) are not Ready. Investigate node conditions before scaling. Remaining nodes are overloaded at %.0f%% memory.",
				sig.notReady, sig.memPct)
		}
		return fmt.Sprintf("Resource exhaustion detected. Add %d node(s) to bring utilization below 70%%.", needed)

	case "strained":
		needed := nodesNeeded(sig, 70.0)
		if sig.schedFail {
			return fmt.Sprintf(
				"FailedScheduling events indicate insufficient capacity. Add %d node(s) or reduce workload resource requests.",
				needed)
		}
		if sig.memPct > 85 {
			return fmt.Sprintf(
				"Memory at %.0f%% with no pressure yet, but little headroom remains. Consider adding %d node(s) proactively.",
				sig.memPct, needed)
		}
		return fmt.Sprintf(
			"Utilization is elevated (CPU %.0f%%, memory %.0f%%). Monitor closely. %d additional node(s) would bring usage below 70%%.",
			sig.cpuPct, sig.memPct, needed)

	case "busy":
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

// nodesNeeded calculates how many additional nodes are required to bring
// memory utilization below the target percentage, assuming each new node
// adds the same capacity as existing nodes.
func nodesNeeded(sig clusterSignals, targetPct float64) int {
	if sig.nodeCount == 0 || sig.memPct <= targetPct {
		return 0
	}
	// Total memory units currently used = memPct/100 * nodeCount.
	usedUnits := sig.memPct / 100 * float64(sig.nodeCount)
	// Need: usedUnits / totalNodes <= targetPct/100.
	// totalNodes >= usedUnits / (targetPct/100).
	needed := usedUnits / (targetPct / 100)
	additional := int(math.Ceil(needed)) - sig.nodeCount
	if additional < 1 {
		additional = 1
	}
	return additional
}

// groupComparison compares a cluster to its group peers and describes the deviation.
func groupComparison(cluster, groupName string, peers []string, signals map[string]clusterSignals) string {
	var peerMem []float64
	var peerCPU []float64
	for _, p := range peers {
		if p == cluster {
			continue
		}
		if s, ok := signals[p]; ok {
			peerMem = append(peerMem, s.memPct)
			peerCPU = append(peerCPU, s.cpuPct)
		}
	}
	if len(peerMem) == 0 {
		return ""
	}

	sig := signals[cluster]
	avgPeerMem := avg(peerMem)
	avgPeerCPU := avg(peerCPU)

	memDiff := sig.memPct - avgPeerMem
	cpuDiff := sig.cpuPct - avgPeerCPU

	// Only report if the deviation is significant (>10 percentage points).
	if math.Abs(memDiff) < 10 && math.Abs(cpuDiff) < 10 {
		return fmt.Sprintf("Within normal range for group %q (peers avg: CPU %.0f%%, memory %.0f%%).", groupName, avgPeerCPU, avgPeerMem)
	}

	parts := ""
	if math.Abs(memDiff) >= 10 {
		dir := "higher"
		if memDiff < 0 {
			dir = "lower"
		}
		parts += fmt.Sprintf("Memory is %.0f%% points %s than group %q average (%.0f%% vs %.0f%%). ", math.Abs(memDiff), dir, groupName, sig.memPct, avgPeerMem)
	}
	if math.Abs(cpuDiff) >= 10 {
		dir := "higher"
		if cpuDiff < 0 {
			dir = "lower"
		}
		parts += fmt.Sprintf("CPU is %.0f%% points %s than group %q average (%.0f%% vs %.0f%%).", math.Abs(cpuDiff), dir, groupName, sig.cpuPct, avgPeerCPU)
	}
	return parts
}

// extractAllSignals pulls capacity-relevant data from the report for all clusters.
func extractAllSignals(r *Report) map[string]clusterSignals {
	out := make(map[string]clusterSignals, len(r.Clusters))
	for _, cluster := range r.Clusters {
		var sig clusterSignals
		sig.cpuPct = getFloatField(r, "metrics", cluster, "avg_cpu_percent")
		sig.memPct = getFloatField(r, "metrics", cluster, "avg_memory_percent")
		sig.maxMemPct = getFloatField(r, "metrics", cluster, "max_memory_percent")
		sig.nodeCount = getIntField(r, "node-health", cluster, "node_count")
		sig.healthyNodes = getIntField(r, "node-health", cluster, "healthy_nodes")
		sig.memPressure = getIntField(r, "node-health", cluster, "memory_pressure_nodes")
		sig.diskPressure = getIntField(r, "node-health", cluster, "disk_pressure_nodes")
		sig.notReady = getIntField(r, "node-health", cluster, "not_ready_nodes")
		sig.warnEvents = getIntField(r, "events", cluster, "warning_events")

		// Check for OOM and scheduling events in the event data.
		sig.oomEvents = hasEventReason(r, cluster, "OOMKilling")
		sig.schedFail = hasEventReason(r, cluster, "FailedScheduling")

		out[cluster] = sig
	}
	return out
}

// hasEventReason checks if a cluster has warning events with a specific reason.
func hasEventReason(r *Report, cluster, reason string) bool {
	sec := r.Sections["events"]
	if sec == nil {
		return false
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return false
	}
	b, _ := json.Marshal(data)
	var m map[string]any
	json.Unmarshal(b, &m)
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

// avg computes the average of a float64 slice.
func avg(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}
