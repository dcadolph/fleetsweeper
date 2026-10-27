// Package browser holds the dashboard's browser smoke test. It loads every page of the demo
// server in headless Chrome, fails on any console error or uncaught rejection, and drives the
// scan trigger to its completion toast. Run it with:
//
//	go test -tags=browser ./internal/browser/
package browser
