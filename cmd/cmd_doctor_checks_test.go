package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// newServerCheckCmd returns a command carrying the doctor server-probe flags.
func newServerCheckCmd(addr, token string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("addr", addr, "")
	cmd.Flags().String("token", token, "")
	return cmd
}

// TestDoctorCheckServer verifies skip, healthy, and failing probes.
func TestDoctorCheckServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test 0: No addr skips the check.
	if got := doctorCheckServer(ctx, newServerCheckCmd("", "")); got.Status != StatusSkip {
		t.Errorf("no addr: got %s, want skip", got.Status)
	}

	// Test 1: A server that answers 200 on both probes is healthy.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if got := doctorCheckServer(ctx, newServerCheckCmd(ok.URL, "secret")); got.Status != StatusOK {
		t.Errorf("healthy: got %s (%s), want ok", got.Status, got.Detail)
	}

	// Test 2: A server returning 500 fails the check.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if got := doctorCheckServer(ctx, newServerCheckCmd(bad.URL, "")); got.Status != StatusFail {
		t.Errorf("unhealthy: got %s, want fail", got.Status)
	}
}

// newFreshnessCmd returns a command carrying the scan-freshness flags.
func newFreshnessCmd(dbPath string, maxAge time.Duration) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("db", dbPath, "")
	cmd.Flags().String("db-driver", "", "")
	cmd.Flags().Duration("scan-freshness", maxAge, "")
	return cmd
}

// TestDoctorCheckScanFreshness verifies skip, warn, ok, and stale outcomes.
func TestDoctorCheckScanFreshness(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test 0: No db skips.
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd("", time.Hour)); got.Status != StatusSkip {
		t.Errorf("no db: got %s, want skip", got.Status)
	}

	// Test 1: Empty store warns.
	emptyPath := filepath.Join(t.TempDir(), "empty.db")
	if s, err := store.NewSQLite(emptyPath); err != nil {
		t.Fatalf("open empty: %v", err)
	} else {
		s.Close()
	}
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(emptyPath, time.Hour)); got.Status != StatusWarn {
		t.Errorf("empty store: got %s, want warn", got.Status)
	}

	// Test 2: A fresh scan within the window is ok.
	freshPath := filepath.Join(t.TempDir(), "fresh.db")
	seedHistoryScans(t, freshPath, 1)
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(freshPath, 24*time.Hour)); got.Status != StatusOK {
		t.Errorf("fresh scan: got %s (%s), want ok", got.Status, got.Detail)
	}

	// Test 3: A near-zero freshness window makes the same scan read as stale.
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(freshPath, time.Nanosecond)); got.Status != StatusFail {
		t.Errorf("stale scan: got %s, want fail", got.Status)
	}
}

// newKubeconfigCmd returns a command carrying only a kubeconfig flag.
func newKubeconfigCmd(path string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("kubeconfig", path, "")
	return cmd
}

// newDBCheckCmd returns a command carrying the db and db-driver flags.
func newDBCheckCmd(dbPath, driver string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("db", dbPath, "")
	cmd.Flags().String("db-driver", driver, "")
	return cmd
}

// TestDoctorCheckKubeconfig verifies skip, missing-file, and valid-parse paths.
func TestDoctorCheckKubeconfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if got := doctorCheckKubeconfig(ctx, newKubeconfigCmd("")); got.Status != StatusSkip {
		t.Errorf("empty: got %s, want skip", got.Status)
	}
	if got := doctorCheckKubeconfig(ctx, newKubeconfigCmd(filepath.Join(t.TempDir(), "absent"))); got.Status != StatusFail {
		t.Errorf("missing: got %s, want fail", got.Status)
	}

	kc := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kc, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	if got := doctorCheckKubeconfig(ctx, newKubeconfigCmd(kc)); got.Status != StatusOK {
		t.Errorf("valid: got %s (%s), want ok", got.Status, got.Detail)
	}
}

// TestDoctorCheckDatabase verifies skip, ok, and bad-driver failure.
func TestDoctorCheckDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if got := doctorCheckDatabase(ctx, newDBCheckCmd("", "")); got.Status != StatusSkip {
		t.Errorf("no db: got %s, want skip", got.Status)
	}

	dbPath := filepath.Join(t.TempDir(), "d.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("seed: %v", err)
	} else {
		s.Close()
	}
	if got := doctorCheckDatabase(ctx, newDBCheckCmd(dbPath, "")); got.Status != StatusOK {
		t.Errorf("valid db: got %s (%s), want ok", got.Status, got.Detail)
	}
	if got := doctorCheckDatabase(ctx, newDBCheckCmd(dbPath, "bogus-driver")); got.Status != StatusFail {
		t.Errorf("bad driver: got %s, want fail", got.Status)
	}
}

// newInClusterCmd returns a command carrying the in-cluster check flags.
func newInClusterCmd(release string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("kubeconfig", "unused", "")
	cmd.Flags().String("namespace", "fleetsweeper", "")
	cmd.Flags().String("release", release, "")
	return cmd
}

// TestDoctorInClusterChecks verifies the lease and webhook checks use the release names.
func TestDoctorInClusterChecks(t *testing.T) {
	t.Parallel()
	holder := "pod-0"
	lease := func(name string, h *string) *coordinationv1.Lease {
		return &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "fleetsweeper"},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: h},
		}
	}
	type vwc = admissionv1.ValidatingWebhookConfiguration
	webhook := func(name string, hook admissionv1.ValidatingWebhook) *vwc {
		return &vwc{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Webhooks:   []admissionv1.ValidatingWebhook{hook},
		}
	}
	svcHook := admissionv1.ValidatingWebhook{
		Name: "v.fleetsweeper.io",
		ClientConfig: admissionv1.WebhookClientConfig{
			Service: &admissionv1.ServiceReference{Name: "fleetsweeper-admission"},
		},
	}
	bareHook := admissionv1.ValidatingWebhook{Name: "v.fleetsweeper.io"}

	tests := []struct {
		Check      func(context.Context, *cobra.Command, doctorClientFunc) CheckResult
		Release    string
		WantStatus Status
		Objects    []any
	}{
		{ // Test 0: Held lease named for the release is OK.
			Check: doctorCheckLeaderLease, Release: "fleetsweeper", WantStatus: StatusOK,
			Objects: []any{lease("fleetsweeper", &holder)},
		},
		{ // Test 1: Missing lease warns.
			Check: doctorCheckLeaderLease, Release: "fleetsweeper", WantStatus: StatusWarn,
		},
		{ // Test 2: Lease named for a custom release is found.
			Check: doctorCheckLeaderLease, Release: "prod", WantStatus: StatusOK,
			Objects: []any{lease("prod", &holder)},
		},
		{ // Test 3: Webhook configuration named for the release is OK.
			Check: doctorCheckAdmissionWebhook, Release: "fleetsweeper", WantStatus: StatusOK,
			Objects: []any{webhook("fleetsweeper-admission", svcHook)},
		},
		{ // Test 4: Webhook with no CA and no Service fails.
			Check: doctorCheckAdmissionWebhook, Release: "fleetsweeper", WantStatus: StatusFail,
			Objects: []any{webhook("fleetsweeper-admission", bareHook)},
		},
		{ // Test 5: Missing webhook configuration warns.
			Check: doctorCheckAdmissionWebhook, Release: "fleetsweeper", WantStatus: StatusWarn,
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fake.NewSimpleClientset()
			for _, obj := range test.Objects {
				var err error
				switch o := obj.(type) {
				case *coordinationv1.Lease:
					_, err = cs.CoordinationV1().Leases(o.Namespace).Create(
						context.Background(), o, metav1.CreateOptions{})
				case *admissionv1.ValidatingWebhookConfiguration:
					_, err = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(
						context.Background(), o, metav1.CreateOptions{})
				}
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			newClient := func(context.Context, string) (*kube.Client, error) {
				return kube.NewTestClientWithClientset("test", cs), nil
			}
			got := test.Check(context.Background(), newInClusterCmd(test.Release), newClient)
			if got.Status != test.WantStatus {
				t.Errorf("got %s (%s), want %s", got.Status, got.Detail, test.WantStatus)
			}
		})
	}
}
