package server

import "errors"

var (
	// ErrServer indicates a general server failure.
	ErrServer = errors.New("server")
	// ErrBadRequest indicates invalid client input.
	ErrBadRequest = errors.New("bad request")
	// ErrMissingCredential indicates a request with no credential to a server that holds one.
	ErrMissingCredential = errors.New("credential required")
)
