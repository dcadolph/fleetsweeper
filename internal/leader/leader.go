// Package leader provides a thin Kubernetes Lease-based leader election
// wrapper. It is used by `serve` to ensure only one replica fires side
// effects (scheduled scans, controller reconciliation, outbound webhook
// dispatch) at a time when fleetsweeper is deployed with replicaCount > 1
// against a shared Postgres backend.
package leader

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Config configures a leader election session.
type Config struct {
	// Namespace is where the Lease object lives. Required; usually the
	// deployment's own namespace, available as the POD_NAMESPACE env var.
	Namespace string
	// Name is the Lease object name. Defaults to "fleetsweeper" when empty.
	Name string
	// Identity uniquely identifies this replica. Usually the pod name from
	// the POD_NAME env var. Defaults to the hostname when empty.
	Identity string
	// LeaseDuration is the lease validity window. Default 30s.
	LeaseDuration time.Duration
	// RenewDeadline is how long the leader has to renew before losing
	// leadership. Default 20s.
	RenewDeadline time.Duration
	// RetryPeriod is how often non-leaders attempt acquisition. Default 5s.
	RetryPeriod time.Duration
	// Log is the structured logger.
	Log *zap.Logger
}

// Callbacks define what happens when leadership state transitions.
type Callbacks struct {
	// OnStartedLeading is called once when this replica becomes leader.
	// The context expires when leadership is lost so the work can cancel.
	OnStartedLeading func(ctx context.Context)
	// OnStoppedLeading is called when leadership is voluntarily released
	// or revoked.
	OnStoppedLeading func()
	// OnNewLeader is called whenever a leader change is observed,
	// including when this replica becomes leader. identity is the new
	// leader's identity string.
	OnNewLeader func(identity string)
}

// Run blocks executing leader election until ctx is cancelled. On success
// the supplied callbacks fire as documented.
func Run(ctx context.Context, cfg Config, cb Callbacks) error {
	if cfg.Namespace == "" {
		return fmt.Errorf("leader: Namespace required")
	}
	if cfg.Log == nil {
		return fmt.Errorf("leader: Log required")
	}
	if cfg.Name == "" {
		cfg.Name = "fleetsweeper"
	}
	if cfg.Identity == "" {
		host, _ := os.Hostname()
		cfg.Identity = host
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 30 * time.Second
	}
	if cfg.RenewDeadline <= 0 {
		cfg.RenewDeadline = 20 * time.Second
	}
	if cfg.RetryPeriod <= 0 {
		cfg.RetryPeriod = 5 * time.Second
	}

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("leader: in-cluster config: %w", err)
	}
	coordination, err := coordinationv1client.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("leader: build client: %w", err)
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metaObject(cfg.Namespace, cfg.Name),
		Client:    coordination,
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: cfg.Identity,
		},
	}

	cfg.Log.Info("leader election starting",
		zap.String("namespace", cfg.Namespace),
		zap.String("name", cfg.Name),
		zap.String("identity", cfg.Identity),
	)

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   cfg.LeaseDuration,
		RenewDeadline:   cfg.RenewDeadline,
		RetryPeriod:     cfg.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				cfg.Log.Info("leader: acquired", zap.String("identity", cfg.Identity))
				if cb.OnStartedLeading != nil {
					cb.OnStartedLeading(leaderCtx)
				}
			},
			OnStoppedLeading: func() {
				cfg.Log.Info("leader: lost or released", zap.String("identity", cfg.Identity))
				if cb.OnStoppedLeading != nil {
					cb.OnStoppedLeading()
				}
			},
			OnNewLeader: func(identity string) {
				cfg.Log.Info("leader: observed", zap.String("leader", identity))
				if cb.OnNewLeader != nil {
					cb.OnNewLeader(identity)
				}
			},
		},
	})
	return nil
}

// IsInCluster reports whether the process appears to be running inside a
// Kubernetes pod. Leader election uses Kubernetes Leases, so it is a no-op
// outside the cluster and should be skipped.
func IsInCluster() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}
