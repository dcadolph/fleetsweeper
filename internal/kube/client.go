package kube

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/dcadolph/fleetsweeper/internal/logutil"
)

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

// NewClient creates a Client connected to the named kubeconfig context.
func NewClient(ctx context.Context, kubeconfigPath, contextName string) (*Client, error) {
	overrides := &clientcmd.ConfigOverrides{
		CurrentContext: contextName,
	}
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrLoadConfig, contextName, err)
	}

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

// ConnectAll connects to the given kubeconfig contexts concurrently. Unreachable
// clusters are logged as warnings and excluded from the result.
func ConnectAll(ctx context.Context, kubeconfigPath string, contexts []string, workers int) []*Client {
	log := logutil.UnwrapLogger(ctx)

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
	return names
}
