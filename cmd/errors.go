package cmd

import "errors"

var (
	// ErrNoContexts indicates no kubeconfig contexts were found or specified.
	ErrNoContexts = errors.New("no kubeconfig contexts specified")
	// ErrNoClients indicates all cluster connections failed.
	ErrNoClients = errors.New("no clusters reachable")
)
