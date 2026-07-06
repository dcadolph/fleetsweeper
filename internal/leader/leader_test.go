package leader

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestRunWithClientConfigValidation verifies required fields are enforced.
func TestRunWithClientConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Cfg     Config
		WantErr string
	}{{ // Test 0: Missing namespace.
		Cfg:     Config{Log: zap.NewNop()},
		WantErr: "leader: Namespace required",
	}, { // Test 1: Missing logger.
		Cfg:     Config{Namespace: "fleet"},
		WantErr: "leader: Log required",
	}}
	for testNum, test := range tests {
		err := RunWithClient(context.Background(), test.Cfg, Callbacks{}, fake.NewClientset().CoordinationV1())
		if err == nil || err.Error() != test.WantErr {
			t.Errorf("test %d: error = %v, want %q", testNum, err, test.WantErr)
		}
	}
}

// TestRunWithClientAcquiresAndReleases verifies a single replica acquires the
// lease, fires the leading callbacks, and releases the lease on cancel.
func TestRunWithClientAcquiresAndReleases(t *testing.T) {
	t.Parallel()
	clientset := fake.NewClientset()
	started := make(chan struct{})
	stopped := make(chan struct{})
	observed := make(chan string, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- RunWithClient(ctx, Config{
			Namespace:     "fleet",
			Name:          "fleetsweeper-test",
			Identity:      "replica-0",
			LeaseDuration: 2 * time.Second,
			RenewDeadline: time.Second,
			RetryPeriod:   200 * time.Millisecond,
			Log:           zap.NewNop(),
		}, Callbacks{
			OnStartedLeading: func(context.Context) { close(started) },
			OnStoppedLeading: func() { close(stopped) },
			OnNewLeader:      func(id string) { observed <- id },
		}, clientset.CoordinationV1())
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("replica did not acquire leadership")
	}
	select {
	case id := <-observed:
		if id != "replica-0" {
			t.Errorf("observed leader = %q, want replica-0", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnNewLeader did not fire")
	}

	lease, err := clientset.CoordinationV1().Leases("fleet").
		Get(context.Background(), "fleetsweeper-test", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "replica-0" {
		t.Errorf("lease holder = %v, want replica-0", lease.Spec.HolderIdentity)
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("OnStoppedLeading did not fire after cancel")
	}
	if err := <-runDone; err != nil {
		t.Fatalf("RunWithClient returned error: %v", err)
	}

	// ReleaseOnCancel clears the holder so the next replica takes over fast.
	lease, err = clientset.CoordinationV1().Leases("fleet").
		Get(context.Background(), "fleetsweeper-test", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease after release: %v", err)
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
		t.Errorf("lease holder after release = %q, want empty", *lease.Spec.HolderIdentity)
	}
}
