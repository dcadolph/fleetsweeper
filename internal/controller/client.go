package controller

import (
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DynamicClient builds a dynamic.Interface suitable for the controller.
// When kubeconfigPath is empty and an in-cluster service-account token exists,
// the in-cluster configuration is preferred so the operator can run as a
// Deployment without extra wiring.
func DynamicClient(kubeconfigPath, contextName string) (dynamic.Interface, error) {
	cfg, err := loadConfig(kubeconfigPath, contextName)
	if err != nil {
		return nil, err
	}
	cfg.UserAgent = "fleetsweeper-controller"
	return dynamic.NewForConfig(cfg)
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
