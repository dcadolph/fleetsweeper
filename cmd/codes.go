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
	// CodeNoDB indicates the --db flag was required but not provided.
	CodeNoDB = 4
	// CodeStoreError indicates a database storage failure.
	CodeStoreError = 5
)
