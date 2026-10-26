package controller

import (
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Clients builds the dynamic client the controller watches ClusterScans with and the core
// client it records Events through. When kubeconfigPath is empty and an in-cluster
// service-account token exists, the in-cluster configuration is preferred so the operator can
// run as a Deployment without extra wiring.
func Clients(kubeconfigPath, contextName string) (dynamic.Interface, typedcorev1.EventsGetter, error) {
	cfg, err := loadConfig(kubeconfigPath, contextName)
	if err != nil {
		return nil, nil, err
	}
	cfg.UserAgent = "fleetsweeper-controller"
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamic client: %w", err)
	}
	core, err := typedcorev1.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("core client: %w", err)
	}
	return dyn, core, nil
}

// loadConfig is a minimal copy of internal/kube/client.go's loader so the
// controller package does not pull in the scanner kube client dependency.
func loadConfig(kubeconfigPath, contextName string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			cfg, err := rest.InClusterConfig()
			if err == nil {
				return cfg, nil
			}
		}
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return cfg, nil
}
