package server

import (
	"errors"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestParsePositiveInt covers the bounded positive-integer parser.
func TestParsePositiveInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		In         string
		Max        int
		WantResult int
		Want       error
	}{{ // Test 0: In-range value.
		Name: "in range", In: "5", Max: 1000, WantResult: 5,
	}, { // Test 1: Zero is rejected.
		Name: "zero", In: "0", Max: 1000, Want: errInvalidInt,
	}, { // Test 2: Non-numeric is rejected.
		Name: "non numeric", In: "12a", Max: 1000, Want: errInvalidInt,
	}, { // Test 3: Empty is rejected.
		Name: "empty", In: "", Max: 1000, Want: errInvalidInt,
	}, { // Test 4: Over-max saturates to max.
		Name: "over max", In: "1000000", Max: 100, WantResult: 100,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePositiveInt(test.In, test.Max)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: err want %v, got %v", i, test.Want, err)
			}
			if test.Want == nil && got != test.WantResult {
				t.Errorf("test %d: want %d, got %d", i, test.WantResult, got)
			}
		})
	}
}

// TestFilterAlertsByActor covers scope filtering for each role, including the
// empty-cluster fleet-wide rule and the nil-actor pass-through.
func TestFilterAlertsByActor(t *testing.T) {
	t.Parallel()
	// mk builds a fresh slice each call because the filter reuses the
	// backing array in place.
	mk := func() []store.AlertRecord {
		return []store.AlertRecord{
			{Fingerprint: "a", Cluster: "east"},
			{Fingerprint: "b", Cluster: "west"},
			{Fingerprint: "c", Cluster: ""},
		}
	}
	tests := []struct {
		Name      string
		Actor     *Actor
		WantCount int
	}{{ // Test 0: Nil actor passes everything.
		Name: "nil actor", Actor: nil, WantCount: 3,
	}, { // Test 1: Admin sees all alerts.
		Name: "admin", Actor: &Actor{Role: store.RoleAdmin}, WantCount: 3,
	}, { // Test 2: Operator keeps in-scope plus the fleet-wide (empty) alert.
		Name: "operator scoped", Actor: &Actor{Role: store.RoleOperator, ClusterScope: []string{"east"}},
		WantCount: 2,
	}, { // Test 3: Viewer drops the empty-cluster fleet-wide alert.
		Name: "viewer scoped", Actor: &Actor{Role: store.RoleViewer, ClusterScope: []string{"east"}},
		WantCount: 1,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := filterAlertsByActor(mk(), test.Actor, nil)
			if len(got) != test.WantCount {
				t.Errorf("test %d: want %d, got %d (%+v)", i, test.WantCount, len(got), got)
			}
		})
	}
}
