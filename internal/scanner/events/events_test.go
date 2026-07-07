package events

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// warning builds a Warning-type Event whose first and last seen times are
// lastSeen. The scanner leans on the apiserver field selector to return only
// warnings, and the fake clientset ignores field selectors, so tests build
// warning events exclusively.
func warning(namespace, obj, kind, reason string, count int32, lastSeen time.Time) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: namespace, Name: obj + "-evt"},
		InvolvedObject: corev1.ObjectReference{Namespace: namespace, Name: obj, Kind: kind},
		Reason:         reason,
		Message:        reason + " occurred",
		Type:           "Warning",
		Count:          count,
		FirstTimestamp: metav1.NewTime(lastSeen),
		LastTimestamp:  metav1.NewTime(lastSeen),
	}
}

// warningCreatedAt builds a Warning event that carries only a creation
// timestamp, exercising the scanner's fallback when first and last seen are
// both unset.
func warningCreatedAt(namespace, obj, reason string, created time.Time) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			Name:              obj + "-evt",
			CreationTimestamp: metav1.NewTime(created),
		},
		InvolvedObject: corev1.ObjectReference{Namespace: namespace, Name: obj, Kind: "Pod"},
		Reason:         reason,
		Message:        reason + " occurred",
		Type:           "Warning",
		Count:          1,
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	now := time.Now()
	recent := func(d time.Duration) time.Time { return now.Add(-d) }
	old := now.Add(-2 * time.Hour)

	tests := []struct {
		Name              string
		Objects           []runtime.Object
		WantTopReasons    []ReasonSummary
		WantFirstInvolved string
		WantFirstReason   string
		WantTotal         int
		WantWarning       int
		WantNormal        int
		WantRecentCount   int
		WantWindowSeconds int
	}{{ // Test 0: Empty cluster reports no events but keeps the window.
		Name:              "empty",
		WantWindowSeconds: 3600,
	}, { // Test 1: Recent warnings aggregate by reason and sort by last seen.
		Name: "recent warnings",
		Objects: []runtime.Object{
			warning("default", "web-1", "Pod", "OOMKilling", 3, recent(3*time.Minute)),
			warning("default", "web-2", "Pod", "OOMKilling", 2, recent(2*time.Minute)),
			warning("kube-system", "dns", "Pod", "BackOff", 1, recent(1*time.Minute)),
		},
		WantTotal:         3,
		WantWarning:       3,
		WantRecentCount:   3,
		WantWindowSeconds: 3600,
		WantTopReasons: []ReasonSummary{
			{Reason: "OOMKilling", Count: 5, EventCount: 2},
			{Reason: "BackOff", Count: 1, EventCount: 1},
		},
		WantFirstInvolved: "dns",
		WantFirstReason:   "BackOff",
	}, { // Test 2: Events older than the window are dropped.
		Name: "window filters old events",
		Objects: []runtime.Object{
			warning("default", "job-1", "Job", "DeadlineExceeded", 1, recent(5*time.Minute)),
			warning("default", "job-2", "Job", "DeadlineExceeded", 1, old),
		},
		WantTotal:         1,
		WantWarning:       1,
		WantRecentCount:   1,
		WantWindowSeconds: 3600,
		WantTopReasons: []ReasonSummary{
			{Reason: "DeadlineExceeded", Count: 1, EventCount: 1},
		},
		WantFirstInvolved: "job-1",
		WantFirstReason:   "DeadlineExceeded",
	}, { // Test 3: A zero Count is treated as a single occurrence.
		Name: "zero count defaults to one",
		Objects: []runtime.Object{
			warning("default", "pod-x", "Pod", "FailedMount", 0, recent(1*time.Minute)),
		},
		WantTotal:         1,
		WantWarning:       1,
		WantRecentCount:   1,
		WantWindowSeconds: 3600,
		WantTopReasons: []ReasonSummary{
			{Reason: "FailedMount", Count: 1, EventCount: 1},
		},
		WantFirstInvolved: "pod-x",
		WantFirstReason:   "FailedMount",
	}, { // Test 4: An event with only a creation timestamp uses it for both seen times.
		Name: "creation timestamp fallback",
		Objects: []runtime.Object{
			warningCreatedAt("default", "pod-y", "FailedScheduling", recent(1*time.Minute)),
		},
		WantTotal:         1,
		WantWarning:       1,
		WantRecentCount:   1,
		WantWindowSeconds: 3600,
		WantTopReasons: []ReasonSummary{
			{Reason: "FailedScheduling", Count: 1, EventCount: 1},
		},
		WantFirstInvolved: "pod-y",
		WantFirstReason:   "FailedScheduling",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset(test.Objects...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}

			if diff := cmp.Diff(test.WantTotal, data.TotalEvents); diff != "" {
				t.Errorf("total events mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantWarning, data.WarningEvents); diff != "" {
				t.Errorf("warning events mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNormal, data.NormalEvents); diff != "" {
				t.Errorf("normal events mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantWindowSeconds, data.WindowSeconds); diff != "" {
				t.Errorf("window seconds mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantRecentCount, len(data.RecentWarnings)); diff != "" {
				t.Errorf("recent warnings count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantTopReasons, data.TopWarningReasons, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("top warning reasons mismatch (-want +got):\n%s", diff)
			}
			if test.WantFirstInvolved == "" {
				return
			}
			if len(data.RecentWarnings) == 0 {
				t.Fatal("expected at least one recent warning")
			}
			first := data.RecentWarnings[0]
			if diff := cmp.Diff(test.WantFirstInvolved, first.InvolvedObject); diff != "" {
				t.Errorf("first involved object mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstReason, first.Reason); diff != "" {
				t.Errorf("first reason mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTruncateMessage covers the message shortening helper.
func TestTruncateMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In         string
		WantResult string
		MaxLen     int
	}{{ // Test 0: A short message is returned unchanged.
		In: "short", MaxLen: 10, WantResult: "short",
	}, { // Test 1: A message at the limit is returned unchanged.
		In: "abcde", MaxLen: 5, WantResult: "abcde",
	}, { // Test 2: A long message is truncated with a trailing ellipsis.
		In: "abcdef", MaxLen: 5, WantResult: "ab...",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			got := truncateMessage(test.In, test.MaxLen)
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("truncate mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNewScannerListError verifies the scanner wraps list failures with ErrScan.
func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "events", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected ErrScan, got %v", err)
	}
}
