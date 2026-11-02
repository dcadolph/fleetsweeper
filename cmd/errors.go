package cmd

import "errors"

var (
	// ErrNoClients indicates all cluster connections failed.
	ErrNoClients = errors.New("no clusters reachable")
	// ErrNoDatabase indicates no --db was given and no default state store can be derived.
	ErrNoDatabase = errors.New("no database: pass --db or set HOME")
	// ErrDemoDatabase indicates --demo was given a --db, which would seed the demo fleet into a
	// real database.
	ErrDemoDatabase = errors.New("--demo runs on its own in-memory store and does not take --db")
	// ErrStableScans indicates --admission-stable-scans is below one.
	ErrStableScans = errors.New("--admission-stable-scans must be at least 1")
	// ErrFlagValue indicates a flag was given a value outside its allowed set.
	ErrFlagValue = errors.New("invalid flag value")
	// ErrLogLevel indicates --log-level named an unknown level.
	ErrLogLevel = errors.New("invalid log level")
	// ErrNoScans indicates a command needs a stored scan and the store has none.
	ErrNoScans = errors.New("no scans in store: run fleetsweeper scan --db <dsn> first")
	// ErrTooFewScans indicates a scan reference needs more stored scans than the store holds.
	ErrTooFewScans = errors.New("need at least two scans")
)
