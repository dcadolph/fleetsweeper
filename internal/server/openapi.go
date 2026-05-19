package server

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the embedded OpenAPI 3.0 specification, the canonical
// definition of every public Fleetsweeper API endpoint. Served verbatim by
// /openapi.yaml so SDK generators and Swagger UIs can introspect the API.
//
//go:embed openapi.yaml
var openAPISpec []byte

// handleOpenAPI serves the embedded OpenAPI spec as text/yaml.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openAPISpec)
}
