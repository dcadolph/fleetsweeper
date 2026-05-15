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
	// TotalEvents is the total number of events.
	TotalEvents int `json:"total_events"`
	// WarningEvents is the number of Warning-type events.
	WarningEvents int `json:"warning_events"`
	// NormalEvents is the number of Normal-type events.
	NormalEvents int `json:"normal_events"`
	// TopWarningReasons lists the most common warning event reasons.
	TopWarningReasons []ReasonSummary `json:"top_warning_reasons"`
	// RecentWarnings lists the most recent warning events (up to 50).
	RecentWarnings []EventInfo `json:"recent_warnings"`
}

// NewScanner returns a scanner that collects Kubernetes events from a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		eventList, err := client.Clientset().CoreV1().Events("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{TotalEvents: len(eventList.Items)}
		reasonCounts := make(map[string]int32)
		reasonEventCounts := make(map[string]int)

		var warnings []EventInfo
		for _, ev := range eventList.Items {
			switch ev.Type {
			case "Warning":
				data.WarningEvents++
			default:
				data.NormalEvents++
			}

			if ev.Type != "Warning" {
				continue
			}

			count := ev.Count
			if count == 0 {
				count = 1
			}
			reasonCounts[ev.Reason] += count
			reasonEventCounts[ev.Reason]++

			firstSeen := ev.FirstTimestamp.Time
			lastSeen := ev.LastTimestamp.Time
			if firstSeen.IsZero() {
				firstSeen = ev.CreationTimestamp.Time
			}
			if lastSeen.IsZero() {
				lastSeen = ev.CreationTimestamp.Time
			}

			warnings = append(warnings, EventInfo{
				Namespace:      ev.Namespace,
				InvolvedObject: ev.InvolvedObject.Name,
				Kind:           ev.InvolvedObject.Kind,
				Reason:         ev.Reason,
				Message:        truncateMessage(ev.Message, 200),
				Type:           ev.Type,
				Count:          count,
				FirstSeen:      firstSeen.Format(time.RFC3339),
				LastSeen:       lastSeen.Format(time.RFC3339),
			})
		}

		// Sort warnings by last seen descending.
		sort.Slice(warnings, func(i, j int) bool {
			return warnings[i].LastSeen > warnings[j].LastSeen
		})

		// Keep top 50 recent warnings.
		if len(warnings) > 50 {
			warnings = warnings[:50]
		}
		data.RecentWarnings = warnings

		// Build top warning reasons.
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
