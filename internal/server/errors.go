package server

import "errors"

var (
	// ErrServer indicates a general server failure.
	ErrServer = errors.New("server")
	// ErrBadRequest indicates invalid client input.
	ErrBadRequest = errors.New("bad request")
)
