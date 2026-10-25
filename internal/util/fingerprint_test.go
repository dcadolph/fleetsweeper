package util

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestFingerprint checks the hash against hard-coded sha256 values.
func TestFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Cluster       string
		Scanner       string
		Title         string
		WantHash      string
		WantNotEquals string
	}{{ // Test 0: Fixed input matches the sha256 of c, NUL, s, NUL, t.
		Cluster: "c", Scanner: "s", Title: "t",
		WantHash: "741c015adb23e476b173b2ed97e364a8b27a54868012288849d92d0c0739f17e",
	}, { // Test 1: A pipe-separated hash of the same fields differs.
		Cluster: "c", Scanner: "s", Title: "t",
		WantNotEquals: "f2b8419830adc96cb9608c12159c3a759e2cd84505f76e48961ca255c590eaf9",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := Fingerprint(test.Cluster, test.Scanner, test.Title)
			if test.WantNotEquals != "" {
				if got == test.WantNotEquals {
					t.Errorf("fingerprint equals the pipe-separated hash %s", got)
				}
				return
			}
			if diff := cmp.Diff(test.WantHash, got); diff != "" {
				t.Errorf("hash mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
