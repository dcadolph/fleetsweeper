// Package kube wraps client-go and provides Fleetsweeper's connection
// helpers for multi-cluster scans, including QPS/burst tuning, a user
// agent for apiserver audit trails, and concurrent ConnectAll fan-out.
package kube

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/dcadolph/fleetsweeper/internal/logutil"
)

// userAgent identifies fleetsweeper in API server logs and audit trails.
// Operators should be able to recognize traffic from this tool at a glance.
const userAgent = "fleetsweeper"

// defaultQPS and defaultBurst override the client-go defaults of 5/10 which
// throttle every multi-list scanner on any cluster of meaningful size. The
// audit flagged this as a P0; a single fleet sweep was bottlenecked here.
const (
	defaultQPS   = 50
	defaultBurst = 100
)

// defaultClientTimeout is the per-request timeout for all API server calls.
const defaultClientTimeout = 60 * time.Second

// Client wraps a Kubernetes client connection to a single cluster.
type Client struct {
	// Context is the kubeconfig context name this client is connected to.
	Context   string
	clientset kubernetes.Interface
	dynamic   dynamic.Interface
}

// Clientset returns the typed Kubernetes client interface.
func (c *Client) Clientset() kubernetes.Interface {
	return c.clientset
}

// Dynamic returns the dynamic Kubernetes client interface.
func (c *Client) Dynamic() dynamic.Interface {
	return c.dynamic
}

// NewClient creates a Client connected to the named kubeconfig context. When
// kubeconfigPath is empty and the process is running inside a Kubernetes pod
// the in-cluster service account configuration is used instead and the
// "in-cluster" context name is returned.
func NewClient(_ context.Context, kubeconfigPath, contextName string) (*Client, error) {
	cfg, err := loadConfig(kubeconfigPath, contextName)
	if err != nil {
		return nil, err
	}
	tuneConfig(cfg)

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConnect, contextName, err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConnect, contextName, err)
	}

	return &Client{
		Context:   contextName,
		clientset: cs,
		dynamic:   dyn,
	}, nil
}

// loadConfig returns a rest.Config for the named context. When kubeconfigPath
// is empty and an in-cluster ServiceAccount token is present the in-cluster
// configuration is preferred so the tool can run as a Deployment.
func loadConfig(kubeconfigPath, contextName string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			cfg, err := rest.InClusterConfig()
			if err == nil {
				return cfg, nil
			}
		}
	}
	overrides := &clientcmd.ConfigOverrides{
		CurrentContext: contextName,
	}
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrLoadConfig, contextName, err)
	}
	return cfg, nil
}

// tuneConfig applies the QPS, burst, timeout, and user-agent overrides every
// scanner depends on. The user-agent helps operators identify fleetsweeper
// traffic in API server logs.
func tuneConfig(cfg *rest.Config) {
	cfg.QPS = defaultQPS
	cfg.Burst = defaultBurst
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultClientTimeout
	}
	cfg.UserAgent = userAgent
}

// ConnectAll connects to the given kubeconfig contexts concurrently. Unreachable
// clusters are logged as warnings and excluded from the result.
func ConnectAll(ctx context.Context, kubeconfigPath string, contexts []string, workers int) []*Client {
	log := logutil.UnwrapLogger(ctx)
	if workers <= 0 {
		workers = 5
	}

	var (
		mu      sync.Mutex
		clients []*Client
	)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, name := range contexts {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			defer func() { <-sem }()

			c, err := NewClient(ctx, kubeconfigPath, n)
			if err != nil {
				log.Warn("skipping unreachable cluster", logutil.ContextField(n), logutil.ErrorField(err))
				return
			}

			mu.Lock()
			clients = append(clients, c)
			mu.Unlock()
		}(name)
	}

	wg.Wait()
	return clients
}

// AvailableContexts returns all context names defined in the kubeconfig file.
func AvailableContexts(kubeconfigPath string) ([]string, error) {
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	cfg, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadConfig, err)
	}

	return contextNames(cfg), nil
}

// contextNames extracts sorted context names from a kubeconfig.
func contextNames(cfg *api.Config) []string {
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
