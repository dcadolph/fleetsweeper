package kube

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"k8s.io/client-go/rest"
)

// testKubeconfig is a syntactically valid kubeconfig with three out-of-order
// contexts, used to exercise context enumeration and ordering.
const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: zeta
  context: {cluster: c1, user: u1}
- name: alpha
  context: {cluster: c1, user: u1}
- name: mu
  context: {cluster: c1, user: u1}
users:
- name: u1
  user: {}
`

// writeKubeconfig writes testKubeconfig to a temp file and returns its path.
func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// TestAvailableContextsSorted verifies context names are returned in sorted
// order regardless of their order in the kubeconfig.
func TestAvailableContextsSorted(t *testing.T) {
	t.Parallel()

	got, err := AvailableContexts(writeKubeconfig(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff([]string{"alpha", "mu", "zeta"}, got); diff != "" {
		t.Errorf("context order mismatch (-want +got):\n%s", diff)
	}
}

// TestTuneConfig verifies the client tuning overrides the throttling defaults
// and preserves a caller-supplied timeout.
func TestTuneConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name        string
		In          *rest.Config
		WantTimeout time.Duration
	}{{ // Test 0: Zero timeout gets the default.
		Name:        "default timeout",
		In:          &rest.Config{},
		WantTimeout: defaultClientTimeout,
	}, { // Test 1: Non-zero timeout is left untouched.
		Name:        "explicit timeout preserved",
		In:          &rest.Config{Timeout: 5 * time.Second},
		WantTimeout: 5 * time.Second,
	}}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			tuneConfig(test.In)
			if diff := cmp.Diff(float32(defaultQPS), test.In.QPS); diff != "" {
				t.Errorf("QPS mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(defaultBurst, test.In.Burst); diff != "" {
				t.Errorf("burst mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(userAgent, test.In.UserAgent); diff != "" {
				t.Errorf("user agent mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantTimeout, test.In.Timeout); diff != "" {
				t.Errorf("timeout mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNewClientUnknownContext verifies a context absent from the kubeconfig
// surfaces a load error rather than a nil client.
func TestNewClientUnknownContext(t *testing.T) {
	t.Parallel()

	_, err := NewClient(context.Background(), writeKubeconfig(t), "does-not-exist")
	if !errors.Is(err, ErrLoadConfig) {
		t.Fatalf("expected ErrLoadConfig, got %v", err)
	}
}

// TestConnectAllSkipsUnreachable verifies unreachable contexts are dropped
// from the result instead of aborting the fan-out.
func TestConnectAllSkipsUnreachable(t *testing.T) {
	t.Parallel()

	clients := ConnectAll(context.Background(), writeKubeconfig(t), []string{"does-not-exist"}, 2)
	if diff := cmp.Diff(0, len(clients)); diff != "" {
		t.Errorf("expected no clients (-want +got):\n%s", diff)
	}
}

// TestNewTestClientVersion verifies the test helper wires up a discoverable
// server version for scanners that read it.
func TestNewTestClientVersion(t *testing.T) {
	t.Parallel()

	client := NewTestClient("ctx", &TestVersionInfo{GitVersion: "v1.30.2"})
	info, err := client.Clientset().Discovery().ServerVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff("v1.30.2", info.GitVersion); diff != "" {
		t.Errorf("git version mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("ctx", client.Context); diff != "" {
		t.Errorf("context mismatch (-want +got):\n%s", diff)
	}
}

// twoContextKubeconfig points context a at https://a.example and context b at https://b.example.
const twoContextKubeconfig = `apiVersion: v1
kind: Config
current-context: a
clusters:
- name: ca
  cluster:
    server: https://a.example
- name: cb
  cluster:
    server: https://b.example
contexts:
- name: a
  context: {cluster: ca, user: u1}
- name: b
  context: {cluster: cb, user: u1}
users:
- name: u1
  user: {token: t}
`

// TestLoadConfigSelectsContext verifies LoadConfig honors the requested context.
func TestLoadConfigSelectsContext(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(twoContextKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		Want     error
		In       string
		WantHost string
	}{{ // Test 0: Context a.
		In: "a", WantHost: "https://a.example",
	}, { // Test 1: Context b.
		In: "b", WantHost: "https://b.example",
	}, { // Test 2: Unknown context.
		In: "nope", Want: ErrLoadConfig,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cfg, err := LoadConfig(path, test.In)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error = %v, want %v", err, test.Want)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.WantHost, cfg.Host); diff != "" {
				t.Errorf("host mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
