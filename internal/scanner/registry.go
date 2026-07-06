package scanner

import (
	"fmt"
	"maps"
	"sort"
)

// Registry maps scanner names to their implementations.
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]Scanner)}
}

// Register adds a scanner under the given name. Panics on duplicate names.
func (r *Registry) Register(name string, s Scanner) {
	if _, exists := r.scanners[name]; exists {
		panic(fmt.Sprintf("scanner already registered: %s", name))
	}
	r.scanners[name] = s
}

// Get returns the scanner registered under name, or false if not found.
func (r *Registry) Get(name string) (Scanner, bool) {
	s, ok := r.scanners[name]
	return s, ok
}

// Names returns all registered scanner names in sorted order.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns a copy of the internal scanner map.
func (r *Registry) All() map[string]Scanner {
	out := make(map[string]Scanner, len(r.scanners))
	maps.Copy(out, r.scanners)
	return out
}
