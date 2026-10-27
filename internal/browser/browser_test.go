//go:build browser

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

const (
	// settleTimeout bounds how long one view may take to replace its loading state.
	settleTimeout = 15 * time.Second
	// toastTimeout bounds how long the scan.complete toast may take after a trigger.
	toastTimeout = 10 * time.Second
)

// settledJS reports whether #ct has replaced its loading placeholder with a view.
const settledJS = `(() => {
  const ct = document.getElementById('ct');
  return !!ct && ct.children.length > 0 && !ct.querySelector(':scope > .loading');
})()`

// viewStateJS describes what #ct shows: a router error, an empty state, or content.
const viewStateJS = `(() => {
  const ct = document.getElementById('ct');
  const first = ct.firstElementChild;
  if (first && first.classList.contains('empty') && first.textContent.startsWith('Error:')) {
    return 'error: ' + first.textContent;
  }
  const empty = ct.querySelector('[data-empty], .empty');
  if (empty && empty.offsetParent !== null) return 'empty';
  const visual = ct.querySelector('canvas, svg, table');
  if (ct.innerText.trim() !== '' || visual) return 'content';
  return 'blank';
})()`

// consoleLog collects console errors and uncaught exceptions, tagged with the route that was
// on screen when they fired.
type consoleLog struct {
	// mu guards route and errs.
	mu sync.Mutex
	// route is the route currently under test.
	route string
	// errs lists every captured error, prefixed with its route.
	errs []string
}

// setRoute names the route later errors belong to.
func (c *consoleLog) setRoute(r string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.route = r
}

// add records one error against the current route.
func (c *consoleLog) add(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, c.route+": "+msg)
}

// take returns and clears the captured errors.
func (c *consoleLog) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.errs
	c.errs = nil
	return out
}

// listen captures console.error calls and uncaught exceptions, including unhandled promise
// rejections, which Chrome reports as exceptions.
func (c *consoleLog) listen(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			if e.Type != runtime.APITypeError {
				return
			}
			parts := make([]string, 0, len(e.Args))
			for _, a := range e.Args {
				if a.Value != nil {
					parts = append(parts, string(a.Value))
				} else {
					parts = append(parts, a.Description)
				}
			}
			c.add("console.error " + strings.Join(parts, " "))
		case *runtime.EventExceptionThrown:
			d := e.ExceptionDetails
			msg := d.Text
			if d.Exception != nil && d.Exception.Description != "" {
				msg += " " + d.Exception.Description
			}
			c.add("uncaught " + msg)
		}
	})
}

// demoServer starts the demo server in-process on a loopback port, seeded the way
// `serve --demo` seeds it.
func demoServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := server.SeedDemo(t.Context(), st, time.Now().UTC().Truncate(time.Minute)); err != nil {
		t.Fatalf("seed demo: %v", err)
	}
	srv := server.New(server.Config{
		Store: st, Registry: scanner.NewRegistry(), Log: zap.NewNop(), Workers: 2, Demo: true,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	return ts
}

// getJSON decodes a GET from the test server into v.
func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // Test helper against a local server.
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// shotDir returns a directory for per-view screenshots. It is kept and logged when the test
// fails and removed when it passes.
func shotDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fleetsweeper-browser-")
	if err != nil {
		t.Fatalf("screenshot dir: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("screenshots kept in %s", dir)
			return
		}
		_ = os.RemoveAll(dir)
	})
	return dir
}

// newBrowser starts headless Chrome and returns its context.
func newBrowser(t *testing.T) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1440, 900),
		chromedp.Flag("enable-unsafe-swiftshader", true),
	)
	if os.Getenv("CI") != "" {
		// Ubuntu runners block the unprivileged user namespaces Chrome's sandbox needs. The
		// page under test is the local demo, so running it unsandboxed there is safe.
		opts = append(opts, chromedp.NoSandbox)
	}
	actx, cancelAlloc := chromedp.NewExecAllocator(t.Context(), opts...)
	ctx, cancel := chromedp.NewContext(actx, chromedp.WithErrorf(func(format string, args ...any) {
		if !strings.HasPrefix(format, "unhandled") {
			t.Logf("chromedp: "+format, args...)
		}
	}))
	t.Cleanup(func() {
		cancel()
		cancelAlloc()
	})
	if err := chromedp.Run(ctx); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("chrome not available in CI: %v", err)
		}
		t.Skipf("chrome not available: %v", err)
	}
	return ctx
}

// run runs actions under a timeout.
func run(ctx context.Context, timeout time.Duration, actions ...chromedp.Action) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return chromedp.Run(ctx, actions...)
}

// clickWhenPresent waits for the element matching sel and clicks it from inside the page,
// so a re-render between finding and clicking cannot swallow the click.
func clickWhenPresent(sel string) chromedp.Action {
	return chromedp.Poll(fmt.Sprintf(`(() => { const el = document.querySelector(%q); if (!el) return false; el.click(); return true; })()`, sel),
		nil, chromedp.WithPollingTimeout(settleTimeout))
}

// TestDashboardSmoke loads every route of the demo dashboard, fails on any console error or
// uncaught exception, checks each view settles into content or an empty state, and runs the
// scan trigger to its completion toast.
func TestDashboardSmoke(t *testing.T) {
	ts := demoServer(t)
	ctx := newBrowser(t)
	shots := shotDir(t)
	log := &consoleLog{route: "boot"}
	log.listen(ctx)

	var scans []struct {
		ID       string   `json:"id"`
		Clusters []string `json:"clusters"`
	}
	getJSON(t, ts.URL+"/api/scans", &scans)
	if len(scans) == 0 || len(scans[0].Clusters) == 0 {
		t.Fatalf("demo seeded %d scans", len(scans))
	}
	latestCluster := scans[0].Clusters[0]

	err := run(ctx, 30*time.Second,
		chromedp.Navigate(ts.URL+"/"),
		chromedp.Evaluate(`localStorage.setItem('fleetsweeper-welcome-dismissed', '1')`, nil),
		chromedp.Navigate(ts.URL+"/#/"),
		chromedp.Poll(settledJS, nil, chromedp.WithPollingTimeout(settleTimeout)),
	)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}

	var routes []string
	err = run(ctx, 10*time.Second, chromedp.Evaluate(
		`import('/js/routes.js').then((m) => m.ROUTES.map((r) => r.id))`, &routes,
		func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }))
	if err != nil || len(routes) == 0 {
		t.Fatalf("read route table: %v (%d routes)", err, len(routes))
	}
	if errs := log.take(); len(errs) > 0 {
		t.Errorf("errors during boot:\n%s", strings.Join(errs, "\n"))
	}

	for _, id := range routes {
		log.setRoute(id)
		hashJS := fmt.Sprintf(`import('/js/router.js').then((m) => m.hashFor(%q, {cluster: %q, scanId: %q}))`,
			id, latestCluster, scans[0].ID)
		var hash, state string
		var shot []byte
		err := run(ctx, settleTimeout+10*time.Second,
			chromedp.Evaluate(hashJS, &hash, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true)
			}),
			chromedp.ActionFunc(func(ctx context.Context) error {
				return chromedp.Evaluate(fmt.Sprintf(`location.hash = %q`, hash), nil).Do(ctx)
			}),
			chromedp.Sleep(50*time.Millisecond),
			chromedp.Poll(settledJS, nil, chromedp.WithPollingTimeout(settleTimeout)),
			chromedp.Sleep(300*time.Millisecond),
			chromedp.Evaluate(viewStateJS, &state),
			chromedp.CaptureScreenshot(&shot),
		)
		if err != nil {
			t.Errorf("route %s (%s): view never settled: %v", id, hash, err)
			continue
		}
		_ = os.WriteFile(filepath.Join(shots, id+".png"), shot, 0o600)
		t.Logf("route %-10s %-28s %s", id, hash, state)
		if state != "content" && state != "empty" {
			t.Errorf("route %s (%s): view shows %s", id, hash, state)
		}
		if errs := log.take(); len(errs) > 0 {
			t.Errorf("route %s: console errors:\n%s", id, strings.Join(errs, "\n"))
		}
	}

	t.Run("trigger flow", func(t *testing.T) {
		log.setRoute("trigger")
		before := len(scans)
		steps := []struct {
			Name   string
			Action chromedp.Action
		}{
			{"open dashboard", chromedp.Evaluate(`location.hash = '#/'`, nil)},
			{"dashboard settles", chromedp.Poll(settledJS+` && !!document.querySelector('[data-action="trigger-scan"]')`,
				nil, chromedp.WithPollingTimeout(settleTimeout))},
			{"click trigger", clickWhenPresent(`[data-action="trigger-scan"]`)},
			{"confirm in drawer", clickWhenPresent(`.drawer-actions button.btn-ac`)},
			{"scan.complete toast", chromedp.Poll(
				`[...document.querySelectorAll('.toast-msg')].some((e) => e.textContent.startsWith('Scan complete'))`,
				nil, chromedp.WithPollingTimeout(toastTimeout))},
		}
		for _, step := range steps {
			if err := run(ctx, settleTimeout+5*time.Second, step.Action); err != nil {
				var toasts string
				_ = run(ctx, 5*time.Second, chromedp.Evaluate(
					`[...document.querySelectorAll('.toast-msg')].map((e) => e.textContent).join(' | ')`, &toasts))
				t.Fatalf("trigger flow: %s: %v (toasts: %q)", step.Name, err, toasts)
			}
		}
		getJSON(t, ts.URL+"/api/scans", &scans)
		if len(scans) != before+1 {
			t.Errorf("scans: want %d after the trigger, got %d", before+1, len(scans))
		}
		if errs := log.take(); len(errs) > 0 {
			t.Errorf("trigger: console errors:\n%s", strings.Join(errs, "\n"))
		}
	})
}
