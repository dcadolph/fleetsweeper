package server

import (
	"bytes"
	_ "embed"
	"net/http"
	"strconv"
)

// openAPISpec is the embedded OpenAPI 3.0 specification, the canonical
// definition of every public Fleetsweeper API endpoint. Served verbatim by
// /openapi.yaml so SDK generators and Swagger UIs can introspect the API.
//
//go:embed openapi.yaml
var openAPISpec []byte

// openAPIVersionLine is the info.version line of the embedded spec, replaced at serve time.
const openAPIVersionLine = "\n  version: dev\n"

// handleOpenAPI serves the embedded OpenAPI spec as YAML, stamped with the build version.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openAPIDocument(buildInfo.Version))
}

// openAPIDocument returns the embedded spec with info.version set to version.
func openAPIDocument(version string) []byte {
	line := "\n  version: " + strconv.Quote(version) + "\n"
	return bytes.Replace(openAPISpec, []byte(openAPIVersionLine), []byte(line), 1)
}
