package server

import (
	"context"
	"net/http"
	"strings"
)

// parseTagFilter returns a cluster predicate built from any ?tag=K=V
// query parameters (may repeat). When the request carries no tag
// filters the returned predicate always returns true.
//
// Predicate semantics: a cluster matches when it carries every
// (key, value) supplied. Repeated ?tag= entries AND together; multi-
// value matching against a single key is not supported here because
// the conventional model is one value per key per cluster.
func (s *Server) parseTagFilter(ctx context.Context, r *http.Request) (func(cluster string) bool, error) {
	raw := r.URL.Query()["tag"]
	if len(raw) == 0 {
		return func(string) bool { return true }, nil
	}
	wants := make(map[string]string, len(raw))
	for _, t := range raw {
		k, v, ok := strings.Cut(t, "=")
		if !ok || k == "" {
			continue
		}
		wants[k] = v
	}
	if len(wants) == 0 {
		return func(string) bool { return true }, nil
	}
	all, err := s.store.ListClusterTags(ctx)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for cluster, tags := range all {
		match := true
		for k, v := range wants {
			if tags[k] != v {
				match = false
				break
			}
		}
		if match {
			allowed[cluster] = true
		}
	}
	return func(cluster string) bool {
		return allowed[cluster]
	}, nil
}
