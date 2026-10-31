package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// scopeNeed names the scope an actor needs to change a route's server-owned object.
type scopeNeed int

const (
	// needEast means the object lives in cluster east.
	needEast scopeNeed = iota
	// needWildcard means the object spans the fleet, so only wildcard scope reaches it.
	needWildcard
	// needAdmin means the route is for admins whatever their cluster scope.
	needAdmin
)

// scopeCase builds one request against a mutating route.
type scopeCase struct {
	// Name labels the case in failure output.
	Name string
	// Need is the scope the request's target requires.
	Need scopeNeed
	// WantAllowed is the status an actor that meets Need receives.
	WantAllowed int
	// Build seeds the server-owned object and returns the request path under /api and its body.
	Build func(t *testing.T, srv *Server, ss *store.SQLite) (path, body string)
}

// scopeCases returns the scope cases for every mutating API route, keyed by "METHOD path" as
// apiRoutes declares it. Each object the server owns lives in east unless the case names the
// fleet.
func scopeCases() map[string][]scopeCase {
	fixed := func(path, body string) func(*testing.T, *Server, *store.SQLite) (string, string) {
		return func(*testing.T, *Server, *store.SQLite) (string, string) { return path, body }
	}
	seedAck := func(fp, cluster string) func(*testing.T, *Server, *store.SQLite) (string, string) {
		return func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
			t.Helper()
			rec := store.AckRecord{Fingerprint: fp, Cluster: cluster}
			if err := ss.SaveAck(context.Background(), rec); err != nil {
				t.Fatalf("seed ack: %v", err)
			}
			return "/findings/" + fp + "/ack", ""
		}
	}
	seedAlert := func(fp, cluster string) func(*testing.T, *Server, *store.SQLite) (string, string) {
		return func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
			t.Helper()
			if err := ss.UpsertAlert(context.Background(), store.AlertRecord{
				Fingerprint: fp, Cluster: cluster, Status: "firing", AlertName: "Drift",
				ReceivedAt: time.Now(), Labels: map[string]string{}, Annotations: map[string]string{},
			}); err != nil {
				t.Fatalf("seed alert: %v", err)
			}
			return "/alerts/" + fp + "/ack", `{}`
		}
	}
	return map[string][]scopeCase{
		"POST /scans": {{
			Name: "contexts in east", Need: needEast, WantAllowed: http.StatusTooManyRequests,
			Build: func(_ *testing.T, srv *Server, _ *store.SQLite) (string, string) {
				// A held scan slot turns an allowed trigger into 429 instead of a real scan.
				srv.scanBusy.Store(true)
				return "/scans", `{"contexts":["east"]}`
			},
		}},
		"POST /findings/{fingerprint}/ack": {{
			Name: "east finding", Need: needEast, WantAllowed: http.StatusCreated,
			Build: func(t *testing.T, srv *Server, ss *store.SQLite) (string, string) {
				east, _ := seedAckFindings(t, srv, ss)
				return "/findings/" + east.Fingerprint + "/ack", `{}`
			},
		}, {
			Name: "fleet finding", Need: needWildcard, WantAllowed: http.StatusCreated,
			Build: func(t *testing.T, srv *Server, ss *store.SQLite) (string, string) {
				_, fleet := seedAckFindings(t, srv, ss)
				return "/findings/" + fleet.Fingerprint + "/ack", `{}`
			},
		}},
		"DELETE /findings/{fingerprint}/ack": {{
			Name: "east ack", Need: needEast, WantAllowed: http.StatusNoContent,
			Build: seedAck("fp-east", "east"),
		}, {
			Name: "cluster-less ack", Need: needWildcard, WantAllowed: http.StatusNoContent,
			Build: seedAck("fp-blank", ""),
		}},
		"POST /alerts/{fingerprint}/ack": {{
			Name: "east alert", Need: needEast, WantAllowed: http.StatusCreated,
			Build: seedAlert("alert-east", "east"),
		}, {
			Name: "cluster-less alert", Need: needWildcard, WantAllowed: http.StatusCreated,
			Build: seedAlert("alert-blank", ""),
		}},
		"PUT /clusters/{name}/tags/{key}": {{
			Name: "east tag", Need: needEast, WantAllowed: http.StatusOK,
			Build: fixed("/clusters/east/tags/team", `{"value":"core"}`),
		}},
		"DELETE /clusters/{name}/tags/{key}": {{
			Name: "east tag", Need: needEast, WantAllowed: http.StatusNoContent,
			Build: func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
				t.Helper()
				if err := ss.SetClusterTag(context.Background(), "east", "team", "core"); err != nil {
					t.Fatalf("seed tag: %v", err)
				}
				return "/clusters/east/tags/team", ""
			},
		}},
		"PUT /locations/{cluster}": {{
			Name: "east location", Need: needEast, WantAllowed: http.StatusOK,
			Build: fixed("/locations/east", `{"lat":40.7,"lng":-74}`),
		}},
		"DELETE /locations/{cluster}": {{
			Name: "east location", Need: needEast, WantAllowed: http.StatusNoContent,
			Build: func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
				t.Helper()
				rec := store.LocationRecord{Cluster: "east", Lat: 40.7, Lng: -74}
				if err := ss.SetLocation(context.Background(), rec); err != nil {
					t.Fatalf("seed location: %v", err)
				}
				return "/locations/east", ""
			},
		}},
		"POST /whatif": {{
			Name: "east field", Need: needEast, WantAllowed: http.StatusOK,
			Build: func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
				t.Helper()
				privileged := func(n int) map[string]scanner.Result {
					return map[string]scanner.Result{"workload-security": {
						Scanner: "workload-security", State: scanner.StateOK,
						Data: map[string]any{"privileged_containers": n, "total_pods": 10},
					}}
				}
				clusters := []string{"east", "west", "north", "south"}
				results := map[string]map[string]scanner.Result{
					"east": privileged(3), "west": privileged(0),
					"north": privileged(0), "south": privileged(0),
				}
				if _, err := ss.SaveScan(context.Background(), clusters, results); err != nil {
					t.Fatalf("seed scan: %v", err)
				}
				body := `{"cluster":"east","scanner":"workload-security","field":"privileged_containers"}`
				return "/whatif", body
			},
		}},
		"POST /groups": {{
			Name: "group of east", Need: needAdmin, WantAllowed: http.StatusCreated,
			Build: fixed("/groups", `{"name":"edge","clusters":["east"]}`),
		}},
		"DELETE /groups/{name}": {{
			Name: "group of east", Need: needAdmin, WantAllowed: http.StatusNoContent,
			Build: func(t *testing.T, _ *Server, ss *store.SQLite) (string, string) {
				t.Helper()
				if err := ss.SaveGroup(context.Background(), "edge", []string{"east"}); err != nil {
					t.Fatalf("seed group: %v", err)
				}
				return "/groups/edge", ""
			},
		}},
	}
}

// mutatingKeys returns the "METHOD path" key of every route that changes state outside the
// admin and webhook namespaces, which carry their own authorization.
func mutatingKeys(routes []route) []string {
	var keys []string
	for _, r := range routes {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		if strings.HasPrefix(r.Path, "/admin/") || strings.HasPrefix(r.Path, "/webhooks/") {
			continue
		}
		keys = append(keys, r.Method+" "+r.Path)
	}
	return keys
}

// unscopedRoutes returns the mutating route keys that have no scope case.
func unscopedRoutes(routes []route, cases map[string][]scopeCase) []string {
	var missing []string
	for _, key := range mutatingKeys(routes) {
		if len(cases[key]) == 0 {
			missing = append(missing, key)
		}
	}
	return missing
}

// serveRoute registers only the route under key on a fresh mux, so path values resolve as in
// production, and serves the request as actor. It fails the test when apiRoutes has no such key.
func serveRoute(t *testing.T, srv *Server, key string, actor *Actor, path, body string) int {
	t.Helper()
	i := slices.IndexFunc(srv.apiRoutes(), func(r route) bool { return r.Method+" "+r.Path == key })
	if i < 0 {
		t.Fatalf("apiRoutes has no route %q", key)
	}
	r := srv.apiRoutes()[i]
	mux := http.NewServeMux()
	mux.HandleFunc(key, r.Handler)
	req := httptest.NewRequest(r.Method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(withActor(req.Context(), actor))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w.Code
}

// TestMutatingRoutesAreScoped walks every mutating API route and checks that the scope test
// reads the server-owned object: an operator scoped to west is refused an object in east, an
// operator scoped to east is not, fleet-spanning objects need wildcard scope, and group
// management needs the admin role. A mutating route with no case fails the test, so a new
// endpoint cannot ship unscoped.
func TestMutatingRoutesAreScoped(t *testing.T) {
	t.Parallel()
	cases := scopeCases()
	probe, _ := testServer(t)
	if missing := unscopedRoutes(probe.apiRoutes(), cases); len(missing) > 0 {
		t.Fatalf("mutating routes with no scope case: %v", missing)
	}
	for key := range cases {
		if !slices.Contains(mutatingKeys(probe.apiRoutes()), key) {
			t.Errorf("scope case %q matches no mutating route", key)
		}
	}
	tests := []struct {
		Actor *Actor
		Meets []scopeNeed
	}{{ // Test 0: Operator scoped to west reaches nothing in east.
		Actor: scopedOperator("west"),
	}, { // Test 1: Operator scoped to east reaches east objects only.
		Actor: scopedOperator("east"), Meets: []scopeNeed{needEast},
	}, { // Test 2: Operator reaching east through a group.
		Actor: scopedOperator("group:east-only"), Meets: []scopeNeed{needEast},
	}, { // Test 3: Wildcard operator reaches the fleet but cannot manage groups.
		Actor: scopedOperator(store.ScopeWildcard), Meets: []scopeNeed{needEast, needWildcard},
	}, { // Test 4: Admin reaches everything.
		Actor: adminActor(), Meets: []scopeNeed{needEast, needWildcard, needAdmin},
	}}
	for testNum, test := range tests {
		for key, scs := range cases {
			for _, sc := range scs {
				t.Run(fmt.Sprintf("test %d/%s/%s", testNum, key, sc.Name), func(t *testing.T) {
					t.Parallel()
					srv, ss := testServer(t)
					if err := ss.SaveGroup(context.Background(), "east-only", []string{"east"}); err != nil {
						t.Fatalf("seed group: %v", err)
					}
					path, body := sc.Build(t, srv, ss)
					want := http.StatusForbidden
					if slices.Contains(test.Meets, sc.Need) {
						want = sc.WantAllowed
					}
					if got := serveRoute(t, srv, key, test.Actor, path, body); got != want {
						t.Errorf("%s %s: want %d, got %d", key, path, want, got)
					}
				})
			}
		}
	}
}

// TestUnscopedRoutesNamesMissing verifies the route walk names a mutating route with no scope
// case and ignores reads, admin routes, and webhooks.
func TestUnscopedRoutesNamesMissing(t *testing.T) {
	t.Parallel()
	probe, _ := testServer(t)
	tests := []struct {
		Extra       []route
		WantMissing []string
	}{{ // Test 0: The real route table is fully covered.
		Extra: nil, WantMissing: nil,
	}, { // Test 1: A new POST route with no case is named.
		Extra:       []route{{Method: http.MethodPost, Path: "/fake/{id}"}},
		WantMissing: []string{"POST /fake/{id}"},
	}, { // Test 2: Reads, admin routes, and webhooks need no case.
		Extra: []route{
			{Method: http.MethodGet, Path: "/fake"},
			{Method: http.MethodPost, Path: "/admin/fake"},
			{Method: http.MethodPost, Path: "/webhooks/fake"},
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			routes := append(probe.apiRoutes(), test.Extra...)
			got := unscopedRoutes(routes, scopeCases())
			if diff := cmp.Diff(test.WantMissing, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("missing mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
