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
	// ErrDuplicate indicates a write collided with an existing unique record.
	ErrDuplicate = errors.New("duplicate")
	// ErrInvalid indicates a write was rejected because a record failed validation.
	ErrInvalid = errors.New("invalid")
)
