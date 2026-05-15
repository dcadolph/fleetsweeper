package cmd

const (
	// CodeSuccess indicates the command completed successfully.
	CodeSuccess = 0
	// CodeGeneralError indicates an unspecified error.
	CodeGeneralError = 1
	// CodeConnectionError indicates a failure connecting to one or more clusters.
	CodeConnectionError = 2
	// CodeNoContexts indicates no kubeconfig contexts were resolved.
	CodeNoContexts = 3
)
