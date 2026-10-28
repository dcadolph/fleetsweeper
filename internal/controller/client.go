package controller

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// Clients builds the dynamic client the controller watches ClusterScans with and the core
// client it records Events through. When kubeconfigPath is empty and an in-cluster
// service-account token exists, the in-cluster configuration is preferred so the operator can
// run as a Deployment without extra wiring.
func Clients(kubeconfigPath, contextName string) (dynamic.Interface, typedcorev1.EventsGetter, error) {
	cfg, err := kube.LoadConfig(kubeconfigPath, contextName)
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
