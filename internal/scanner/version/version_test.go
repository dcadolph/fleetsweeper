package version

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantVersion string
		Want        error
		ServerInfo  *kube.TestVersionInfo
	}{{ // Test 0: Successful version scan.
		ServerInfo:  &kube.TestVersionInfo{Major: "1", Minor: "28", GitVersion: "v1.28.3", Platform: "linux/amd64"},
		WantVersion: "v1.28.3",
		Want:        nil,
	}, { // Test 1: Different version.
		ServerInfo:  &kube.TestVersionInfo{Major: "1", Minor: "29", GitVersion: "v1.29.0", Platform: "linux/arm64"},
		WantVersion: "v1.29.0",
		Want:        nil,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			client := kube.NewTestClient("test-context", test.ServerInfo)
			s := NewScanner()
			result, err := s.Scan(context.Background(), client)
			if test.Want != nil && err == nil {
				t.Fatal("expected error, got nil")
			}
			if test.Want == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}

			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			if diff := cmp.Diff(test.WantVersion, data.GitVersion); diff != "" {
				t.Errorf("version mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
