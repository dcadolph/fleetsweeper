// Package events scans the apiserver's recent Event stream and
// aggregates per-namespace warning counts, surfacing clusters whose
// signal-to-noise has degraded.
package events

import (
	"context"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "events"

// warningWindow caps how far back the scanner looks. A wide-open list call on
// busy clusters frequently returns tens of thousands of stale records and can
// overload the apiserver; restricting to the most recent hour keeps the
// signal-to-noise ratio high.
const warningWindow = time.Hour

// maxRecentWarnings is the cap on warning detail rows returned per cluster.
const maxRecentWarnings = 50

// EventInfo describes a single Kubernetes event.
type EventInfo struct {
	// Namespace is the namespace of the involved object.
	Namespace string `json:"namespace"`
	// InvolvedObject describes the object this event is about.
	InvolvedObject string `json:"involved_object"`
	// Kind is the kind of the involved object (Pod, Node, etc.).
	Kind string `json:"kind"`
	// Reason is the short machine-readable reason.
	Reason string `json:"reason"`
	// Message is the human-readable event message.
	Message string `json:"message"`
	// Type is Normal or Warning.
	Type string `json:"type"`
	// Count is how many times this event has occurred.
	Count int32 `json:"count"`
	// FirstSeen is when the event was first observed.
	FirstSeen string `json:"first_seen"`
	// LastSeen is when the event was last observed.
	LastSeen string `json:"last_seen"`
}

// ReasonSummary aggregates events by reason.
type ReasonSummary struct {
	// Reason is the event reason.
	Reason string `json:"reason"`
	// Count is the total occurrences across all events with this reason.
	Count int32 `json:"count"`
	// EventCount is the number of distinct events with this reason.
	EventCount int `json:"event_count"`
}

// Data holds event information for one cluster.
type Data struct {
	// TotalEvents is the total number of warning events within the time window.
	TotalEvents int `json:"total_events"`
	// WarningEvents is the number of Warning-type events within the window.
	WarningEvents int `json:"warning_events"`
	// NormalEvents is always zero (kept for backward compatibility); the scanner
	// no longer ingests Normal events because they are pure noise at fleet scale.
	NormalEvents int `json:"normal_events"`
	// TopWarningReasons lists the most common warning event reasons.
	TopWarningReasons []ReasonSummary `json:"top_warning_reasons"`
	// RecentWarnings lists the most recent warning events.
	RecentWarnings []EventInfo `json:"recent_warnings"`
	// WindowSeconds is the lookback window the scan honored, in seconds.
	WindowSeconds int `json:"window_seconds"`
}

// NewScanner returns a scanner that collects Kubernetes warning events from
// the most recent warningWindow only. The field selector pushes the type
// filter to the apiserver so a 200-node cluster with thousands of Normal
// events does not stream all of them across the wire.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		cutoff := time.Now().Add(-warningWindow)
		eventList, err := client.Clientset().CoreV1().Events("").List(ctx, metav1.ListOptions{
			FieldSelector:        "type=Warning",
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{WindowSeconds: int(warningWindow.Seconds())}
		reasonCounts := make(map[string]int32)
		reasonEventCounts := make(map[string]int)

		var warnings []EventInfo
		for _, ev := range eventList.Items {
			lastSeen := ev.LastTimestamp.Time
			if lastSeen.IsZero() {
				lastSeen = ev.CreationTimestamp.Time
			}
			if lastSeen.Before(cutoff) {
				continue
			}

			data.WarningEvents++
			data.TotalEvents++

			count := ev.Count
			if count == 0 {
				count = 1
			}
			reasonCounts[ev.Reason] += count
			reasonEventCounts[ev.Reason]++

			firstSeen := ev.FirstTimestamp.Time
			if firstSeen.IsZero() {
				firstSeen = ev.CreationTimestamp.Time
			}

			warnings = append(warnings, EventInfo{
				Namespace:      ev.Namespace,
				InvolvedObject: ev.InvolvedObject.Name,
				Kind:           ev.InvolvedObject.Kind,
				Reason:         ev.Reason,
				Message:        truncateMessage(ev.Message, 500),
				Type:           ev.Type,
				Count:          count,
				FirstSeen:      firstSeen.Format(time.RFC3339),
				LastSeen:       lastSeen.Format(time.RFC3339),
			})
		}

		sort.Slice(warnings, func(i, j int) bool {
			return warnings[i].LastSeen > warnings[j].LastSeen
		})
		if len(warnings) > maxRecentWarnings {
			warnings = warnings[:maxRecentWarnings]
		}
		data.RecentWarnings = warnings

		for reason, count := range reasonCounts {
			data.TopWarningReasons = append(data.TopWarningReasons, ReasonSummary{
				Reason:     reason,
				Count:      count,
				EventCount: reasonEventCounts[reason],
			})
		}
		sort.Slice(data.TopWarningReasons, func(i, j int) bool {
			return data.TopWarningReasons[i].Count > data.TopWarningReasons[j].Count
		})
		if len(data.TopWarningReasons) > 10 {
			data.TopWarningReasons = data.TopWarningReasons[:10]
		}

		return scanner.Result{
			Scanner: Name,
			Data:    data,
		}, nil
	})
}

// truncateMessage cuts a message to maxLen and appends ellipsis if needed.
func truncateMessage(msg string, maxLen int) string {
	if len(msg) <= maxLen {
		return msg
	}
	return msg[:maxLen-3] + "..."
}
