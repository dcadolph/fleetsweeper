package cmd

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestOneOf verifies oneOf accepts allowed values and names the flag and choices otherwise.
func TestOneOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Flag        string
		Value       string
		Allowed     []string
		WantMessage string
		Want        error
	}{{ // Test 0: An allowed value passes.
		Flag: "output", Value: "html", Allowed: []string{"json", "html"},
	}, { // Test 1: An unknown value names the flag, the value, and the choices.
		Flag: "output", Value: "yaml", Allowed: []string{"json", "html"},
		WantMessage: `invalid flag value: --output "yaml": want one of json, html`, Want: ErrFlagValue,
	}, { // Test 2: Matching is exact, so case differences fail.
		Flag: "admission-mode", Value: "Enforce", Allowed: []string{"advisory", "enforce"},
		WantMessage: `invalid flag value: --admission-mode "Enforce": want one of advisory, enforce`,
		Want:        ErrFlagValue,
	}, { // Test 3: An empty value passes when empty is allowed.
		Flag: "severity", Value: "", Allowed: []string{"", "critical", "warning", "info"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			err := oneOf(test.Flag, test.Value, test.Allowed...)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error = %v, want %v", err, test.Want)
			}
			if err != nil {
				if diff := cmp.Diff(test.WantMessage, err.Error()); diff != "" {
					t.Errorf("message mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestSelectScanners verifies empty selection returns every scanner, known names select a
// subset, and unknown names fail listing the registered scanners.
func TestSelectScanners(t *testing.T) {
	t.Parallel()
	reg := buildRegistry()
	tests := []struct {
		Names       []string
		WantNames   []string
		WantMessage []string
		Want        error
	}{{ // Test 0: Empty names select every scanner.
		WantNames: reg.Names(),
	}, { // Test 1: A known subset is selected.
		Names: []string{"version", "node-health"}, WantNames: []string{"node-health", "version"},
	}, { // Test 2: An unknown name fails and lists the registered names.
		Names:       []string{"version", "not-a-real-scanner"},
		WantMessage: []string{"not-a-real-scanner", "node-health"},
		Want:        ErrFlagValue,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := selectScanners(reg, test.Names)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error = %v, want %v", err, test.Want)
			}
			for _, m := range test.WantMessage {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("error %q does not mention %q", err, m)
				}
			}
			var names []string
			for n := range got {
				names = append(names, n)
			}
			slices.Sort(names)
			want := slices.Clone(test.WantNames)
			slices.Sort(want)
			if diff := cmp.Diff(want, names, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("selection mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
