package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// testServer creates a Server backed by a temp SQLite database.
func testServer(t *testing.T) (*Server, *store.SQLite) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	registry := scanner.NewRegistry()
	srv := New(Config{
		Store:    s,
		Registry: registry,
		Log:      zap.NewNop(),
		Workers:  2,
		Insecure: true,
	})
	t.Cleanup(func() {
		srv.Close()
		s.Close()
	})
	return srv, s
}

// TestBearerAuth verifies that mutating endpoints reject requests when an auth
// token is configured but the request lacks a matching bearer header, and
// accept requests that carry the correct token.
func TestBearerAuth(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	srv := New(Config{
		Store:     s,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "secret-token",
	})
	t.Cleanup(func() {
		srv.Close()
		s.Close()
	})

	body := `{"name":"prod","clusters":["a","b"]}`

	noAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, noAuth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: want 401, got %d", w.Code)
	}

	wrongAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	wrongAuth.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, wrongAuth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", w.Code)
	}

	rightAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	rightAuth.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, rightAuth)
	if w.Code != http.StatusCreated {
		t.Fatalf("right token: want 201, got %d body %s", w.Code, w.Body.String())
	}

	// GET should always pass when no Authorization header is supplied.
	read := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, read)
	if w.Code != http.StatusOK {
		t.Fatalf("read without token: want 200, got %d", w.Code)
	}
}

// TestHealthz confirms the liveness probe endpoint is unauthenticated and OK.
func TestHealthz(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: status %d", w.Code)
	}
}

func TestListScansEmpty(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if diff := cmp.Diff(http.StatusOK, w.Code); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}

	var scans []any
	json.Unmarshal(w.Body.Bytes(), &scans)
	if scans != nil && len(scans) != 0 {
		t.Errorf("expected empty list, got %d", len(scans))
	}
}

func TestScanRoundTrip(t *testing.T) {
	t.Parallel()
	srv, s := testServer(t)

	// Save a scan directly to the store.
	results := map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
	scanID, err := s.SaveScan(context.Background(), []string{"cluster-a"}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	// List scans via API.
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list scans: status %d", w.Code)
	}

	// Get scan report via API.
	req = httptest.NewRequest(http.MethodGet, "/api/scans/"+scanID+"/report", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get report: status %d, body: %s", w.Code, w.Body.String())
	}

	var rpt map[string]any
	json.Unmarshal(w.Body.Bytes(), &rpt)
	if _, ok := rpt["sections"]; !ok {
		t.Error("report missing sections key")
	}
	if _, ok := rpt["findings"]; !ok {
		t.Error("report missing findings key")
	}
}

func TestGroupAPI(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	// Create group.
	body := `{"name":"prod","clusters":["east","west"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create group: status %d, body: %s", w.Code, w.Body.String())
	}

	// List groups.
	req = httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list groups: status %d", w.Code)
	}

	var groups []map[string]any
	json.Unmarshal(w.Body.Bytes(), &groups)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	// Delete group.
	req = httptest.NewRequest(http.MethodDelete, "/api/groups/prod", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("delete group: status %d", w.Code)
	}
}

func TestStaticIndex(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("index: status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Fleetsweeper") {
		t.Error("index missing Fleetsweeper title")
	}
}

// TestRunScanners covers an empty client list, a scanner that fails, and a canceled context,
// checking every pair is accounted for and failures are recorded as errored, never dropped.
func TestRunScanners(t *testing.T) {
	t.Parallel()
	failing := scanner.ScannerFunc(func(context.Context, *kube.Client) (scanner.Result, error) {
		return scanner.Result{}, errors.New("api unavailable")
	})
	scanners := map[string]scanner.Scanner{"node-health": pressureScanner, "broken": failing}
	kubeconfig := writeTestKubeconfig(t, "east", "west")
	clients := kube.ConnectAll(context.Background(), kubeconfig, []string{"east", "west"}, 2)
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		Ctx        context.Context
		Clients    []*kube.Client
		WantStates map[string]map[string]scanner.State
	}{{ // Test 0: No clients yields an empty, non-nil map.
		Ctx: context.Background(), WantStates: map[string]map[string]scanner.State{},
	}, { // Test 1: A failing scanner is errored and the healthy one is OK on every cluster.
		Ctx: context.Background(), Clients: clients,
		WantStates: map[string]map[string]scanner.State{
			"east": {"node-health": scanner.StateOK, "broken": scanner.StateErrored},
			"west": {"node-health": scanner.StateOK, "broken": scanner.StateErrored},
		},
	}, { // Test 2: A canceled context records every pair as errored instead of omitting it.
		Ctx: canceled, Clients: clients,
		WantStates: map[string]map[string]scanner.State{
			"east": {"node-health": scanner.StateErrored, "broken": scanner.StateErrored},
			"west": {"node-health": scanner.StateErrored, "broken": scanner.StateErrored},
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := RunScanners(test.Ctx, test.Clients, scanners, 2, time.Second, zap.NewNop())
			if got == nil {
				t.Fatal("RunScanners returned nil")
			}
			states := make(map[string]map[string]scanner.State, len(got))
			for cluster, byScanner := range got {
				states[cluster] = make(map[string]scanner.State, len(byScanner))
				for name, res := range byScanner {
					states[cluster][name] = res.State
				}
			}
			if diff := cmp.Diff(test.WantStates, states); diff != "" {
				t.Errorf("states mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// schedulerProbe records the scheduled scans a test scheduler runs.
type schedulerProbe struct {
	// mu guards every field below.
	mu sync.Mutex
	// calls lists the first context of each scheduled scan, in order.
	calls []string
	// active is the number of scheduled scans running right now.
	active int
	// maxActive is the highest value active has reached.
	maxActive int
}

// scan is a scheduledScan replacement that records the call and holds it briefly so overlapping
// schedulers would be visible in maxActive.
func (p *schedulerProbe) scan(_ context.Context, contexts []string) {
	p.mu.Lock()
	p.calls = append(p.calls, contexts[0])
	p.active++
	p.maxActive = max(p.maxActive, p.active)
	p.mu.Unlock()
	time.Sleep(time.Millisecond)
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
}

// count returns how many scheduled scans named context.
func (p *schedulerProbe) count(context string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		if c == context {
			n++
		}
	}
	return n
}

// waitFor polls cond until it holds or two seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// startScheduler runs StartScheduler in a goroutine and returns a channel closed when it returns.
func startScheduler(ctx context.Context, srv *Server, contexts ...string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.StartScheduler(ctx, 5*time.Millisecond, contexts)
	}()
	return done
}

// TestSchedulerStopsWhenContextCanceled verifies canceling the scheduler's context, which is
// how a lost leadership term ends, stops it and no scheduled scan starts afterward.
func TestSchedulerStopsWhenContextCanceled(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	probe := &schedulerProbe{}
	srv.scheduledScan = probe.scan

	ctx, cancel := context.WithCancel(context.Background())
	done := startScheduler(ctx, srv, "east")
	waitFor(t, "two scheduled scans", func() bool { return probe.count("east") >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler kept running after its context was canceled")
	}
	before := probe.count("east")
	time.Sleep(50 * time.Millisecond)
	if after := probe.count("east"); after != before {
		t.Errorf("scheduled scans after cancel: %d started, want 0", after-before)
	}
}

// TestSchedulerStopsOnServerClose verifies the scheduler also stops when the server shuts down,
// even though its own context is still live.
func TestSchedulerStopsOnServerClose(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	probe := &schedulerProbe{}
	srv.scheduledScan = probe.scan

	done := startScheduler(context.Background(), srv, "east")
	waitFor(t, "a scheduled scan", func() bool { return probe.count("east") >= 1 })
	srv.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler kept running after the server closed")
	}
}

// TestSchedulerSingleInstance verifies a second scheduler, as started by a replica that regains
// leadership before the previous term's scheduler has noticed it lost, waits for the first to
// stop instead of running alongside it.
func TestSchedulerSingleInstance(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	probe := &schedulerProbe{}
	srv.scheduledScan = probe.scan

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := startScheduler(firstCtx, srv, "first")
	waitFor(t, "the first term's scan", func() bool { return probe.count("first") >= 1 })

	secondCtx, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	secondDone := startScheduler(secondCtx, srv, "second")
	waitFor(t, "more first-term scans", func() bool { return probe.count("first") >= 5 })
	if n := probe.count("second"); n != 0 {
		t.Fatalf("second scheduler ran %d scans while the first was still running", n)
	}

	cancelFirst()
	<-firstDone
	waitFor(t, "the second term's scan", func() bool { return probe.count("second") >= 1 })
	cancelSecond()
	<-secondDone

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.maxActive != 1 {
		t.Errorf("max concurrent scheduled scans = %d, want 1", probe.maxActive)
	}
}

// TestSchedulerCanceledWhileWaiting verifies a scheduler whose term ends while it waits for the
// slot returns without scanning.
func TestSchedulerCanceledWhileWaiting(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	probe := &schedulerProbe{}
	srv.scheduledScan = probe.scan

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	startScheduler(firstCtx, srv, "first")
	waitFor(t, "the first term's scan", func() bool { return probe.count("first") >= 1 })

	waitingCtx, cancelWaiting := context.WithCancel(context.Background())
	waitingDone := startScheduler(waitingCtx, srv, "waiting")
	cancelWaiting()
	select {
	case <-waitingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting scheduler did not return after its context was canceled")
	}
	if n := probe.count("waiting"); n != 0 {
		t.Errorf("canceled waiting scheduler ran %d scans, want 0", n)
	}
}

// TestSchedulerNoopInputs verifies a zero interval or an empty context list returns at once.
func TestSchedulerNoopInputs(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	probe := &schedulerProbe{}
	srv.scheduledScan = probe.scan
	srv.StartScheduler(context.Background(), 0, []string{"east"})
	srv.StartScheduler(context.Background(), time.Second, nil)
	if n := len(probe.calls); n != 0 {
		t.Errorf("no-op scheduler ran %d scans, want 0", n)
	}
}

// TestScheduledScanCanceledWhileWaitingForLock verifies a scan whose context ends while another
// scan holds the lock fails without scanning or saving anything.
func TestScheduledScanCanceledWhileWaitingForLock(t *testing.T) {
	t.Parallel()
	srv, st := newScanTestServer(t, "east")
	core, logs := observer.New(zap.InfoLevel)
	srv.log = zap.New(core)

	srv.scanMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, err := srv.executeScan(ctx, scanRequest{
			Source: scanSourceScheduled, Contexts: []string{"east"}, Scanners: map[string]scanner.Scanner{
				"node-health": pressureScanner,
			}, Emit: emitAll,
		})
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	srv.scanMu.Unlock()

	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	scans, err := st.ListScans(context.Background(), 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("want no saved scans, got %d", len(scans))
	}
	if n := logs.FilterMessage("scan starting").Len(); n != 0 {
		t.Errorf("scan started %d times after its context was canceled, want 0", n)
	}
}

// TestShutdownRacesListen verifies Shutdown and ListenAndServe can run in either order from
// different goroutines: both servers exist from New, so the race detector sees no unsynchronized
// field access and ListenAndServe returns nil after a graceful shutdown.
func TestShutdownRacesListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ShutdownFirst bool
	}{{ // Test 0: Shutdown before ListenAndServe starts.
		ShutdownFirst: true,
	}, { // Test 1: Shutdown while ListenAndServe is starting.
		ShutdownFirst: false,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			st, err := store.NewSQLite(filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer st.Close()
			srv := New(Config{
				Addr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
				Store: st, Registry: scanner.NewRegistry(), Log: zap.NewNop(), Insecure: true,
			})
			if test.ShutdownFirst {
				if err := srv.Shutdown(context.Background()); err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			}
			errCh := make(chan error, 2)
			go func() { errCh <- srv.ListenAndServe() }()
			go func() { errCh <- srv.ListenAndServeAdmin() }()
			if !test.ShutdownFirst {
				if err := srv.Shutdown(context.Background()); err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			}
			for range 2 {
				select {
				case err := <-errCh:
					if err != nil {
						t.Errorf("listen after shutdown: want nil, got %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("listener did not return after shutdown")
				}
			}
		})
	}
}

// TestAdminServerOptional verifies the admin server exists only when an admin address is set
// and that ListenAndServeAdmin is a no-op without one.
func TestAdminServerOptional(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	if srv.adminServer != nil {
		t.Fatal("admin server built without an admin address")
	}
	if err := srv.ListenAndServeAdmin(); err != nil {
		t.Errorf("ListenAndServeAdmin without an address: %v", err)
	}
	if srv.httpServer.Addr != ":8080" {
		t.Errorf("default addr = %q, want :8080", srv.httpServer.Addr)
	}
}
