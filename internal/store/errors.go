package store

import "errors"

var (
	// ErrStore indicates a general storage failure.
	ErrStore = errors.New("store")
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrQuery indicates a failure executing a database query.
	ErrQuery = errors.New("query")
	// ErrMigrate indicates a failure applying schema migrations.
	ErrMigrate = errors.New("migrate")
)
