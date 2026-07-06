package kube

import (
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

// TestVersionInfo holds version data for constructing test clients.
type TestVersionInfo struct {
	// Major is the major version number.
	Major string
	// Minor is the minor version number.
	Minor string
	// GitVersion is the full version string.
	GitVersion string
	// Platform is the server platform string.
	Platform string
}

// NewTestClient creates a Client backed by a fake clientset for testing.
func NewTestClient(contextName string, vi *TestVersionInfo) *Client {
	cs := fakeclientset.NewSimpleClientset()
	if vi != nil {
		fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
		fd.FakedServerVersion = &version.Info{
			Major:      vi.Major,
			Minor:      vi.Minor,
			GitVersion: vi.GitVersion,
			Platform:   vi.Platform,
		}
	}
	return &Client{
		Context:   contextName,
		clientset: cs,
	}
}

// NewTestClientWithClientset creates a Client using the provided fake clientset.
func NewTestClientWithClientset(contextName string, cs kubernetes.Interface) *Client {
	return &Client{
		Context:   contextName,
		clientset: cs,
	}
}
