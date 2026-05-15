package kube

import "errors"

var (
	// ErrLoadConfig indicates a failure loading or parsing the kubeconfig file.
	ErrLoadConfig = errors.New("load kubeconfig")
	// ErrConnect indicates a failure connecting to a cluster.
	ErrConnect = errors.New("connect to cluster")
)
