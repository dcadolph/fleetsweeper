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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
	"github.com/google/go-cmp/cmp"
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
	// chromeStartTimeout bounds how long Chrome may take to report its DevTools address.
	chromeStartTimeout = 60 * time.Second
)

// settledJS reports whether #ct has replaced its loading skeleton with a view.
const settledJS = `(() => {
  const ct = document.getElementById('ct');
  return !!ct && ct.children.length > 0 && !ct.querySelector('[data-loading]');
})()`

// emptyTextJS returns the text of the view's visible empty state, or "" when it shows none.
const emptyTextJS = `(() => {
  const el = document.querySelector('#ct [data-empty]');
  return el && el.getClientRects().length ? el.innerText.trim() : '';
})()`

// watchShiftJS starts recording, for the next render, the layout shift score and the height
// of #ct while its loading skeleton shows.
const watchShiftJS = `(() => {
  const ct = document.getElementById('ct');
  const w = { cls: 0, loading: 0 };
  w.po = new PerformanceObserver((list) => {
    list.getEntries().forEach((e) => { if (!e.hadRecentInput) w.cls += e.value; });
  });
  w.po.observe({ type: 'layout-shift' });
  w.mo = new MutationObserver(() => {
    if (!w.loading && ct.querySelector('[data-loading]')) w.loading = ct.getBoundingClientRect().height;
  });
  w.mo.observe(ct, { childList: true });
  window.__fsShift = w;
  return true;
})()`

// readShiftJS stops the recording watchShiftJS started and reports the layout shift score
// and how far the content's height within the first screen strayed from the skeleton's, as
// a share of that screen.
const readShiftJS = `(() => {
  const w = window.__fsShift;
  w.po.disconnect();
  w.mo.disconnect();
  const ct = document.getElementById('ct');
  const top = ct.getBoundingClientRect().top + window.scrollY;
  const fold = Math.max(1, window.innerHeight - top);
  const fill = (h) => Math.min(h, fold);
  return { cls: w.cls, loading: w.loading, loaded: ct.getBoundingClientRect().height,
    gap: w.loading ? Math.abs(fill(ct.getBoundingClientRect().height) - fill(w.loading)) / fold : -1 };
})()`

// focusRingsJS focuses every visible interactive element on the page in the given theme and
// lists those whose focus ring is missing or contrasts with the page background at less than
// 3:1. A box shadow stands in for an outline only when focus changes it. It restores the
// theme when done.
const focusRingsJS = `((theme) => {
  const root = document.documentElement;
  const prior = root.getAttribute('data-theme');
  root.setAttribute('data-theme', theme);
  const rgb = (c) => {
    const m = /rgba?\(([^)]+)\)/.exec(c || '');
    if (!m) return null;
    const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };
  const lum = (c) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const bg = rgb(getComputedStyle(document.body).backgroundColor);
  const name = (el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') +
    (el.dataset.action ? '[data-action=' + el.dataset.action + ']' : '') + ' "' + (el.textContent || '').trim().slice(0, 24) + '"';
  const sel = 'a[href], button, input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';
  const folded = (el) => { const d = el.closest('details'); return !!d && !d.open && !el.closest('summary'); };
  const els = [...document.querySelectorAll(sel)].filter((el) => !el.disabled && el.getClientRects().length &&
    getComputedStyle(el).visibility !== 'hidden' && !el.closest('[inert], dialog:not([open])') && !folded(el));
  const bad = [];
  let visible = 0;
  const skipped = [];
  els.forEach((el) => {
    if (document.activeElement) document.activeElement.blur();
    const resting = getComputedStyle(el).boxShadow;
    el.focus({ preventScroll: true });
    if (document.activeElement !== el) {
      skipped.push(name(el));
      return;
    }
    if (el.matches(':focus-visible')) visible++;
    const cs = getComputedStyle(el);
    const c = rgb(cs.outlineColor);
    let ok = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1 && !!c && c.a > 0;
    if (ok && bg) {
      const hi = Math.max(lum(c), lum(bg));
      const lo = Math.min(lum(c), lum(bg));
      ok = (hi + 0.05) / (lo + 0.05) >= 3;
    }
    if (!ok && cs.boxShadow !== 'none' && cs.boxShadow !== resting) ok = true;
    if (!ok) bad.push(name(el) + ': outline ' + cs.outlineStyle + ' ' + cs.outlineWidth + ' ' + cs.outlineColor);
  });
  if (document.activeElement) document.activeElement.blur();
  if (prior === null) root.removeAttribute('data-theme'); else root.setAttribute('data-theme', prior);
  return { checked: els.length, visible, skipped, bad };
})`

// Layout bounds for the move from a view's loading skeleton to its content.
const (
	// maxShiftScore bounds the layout shift score of one render, half the web vitals "good" line.
	maxShiftScore = 0.05
	// maxFillGap bounds how far the content's height within the first screen may stray from
	// the skeleton's, as a share of that screen.
	maxFillGap = 0.25
)

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

// demoServer starts the demo server in-process on a loopback port. With seed set its store
// holds the scans `serve --demo` seeds; without it the store holds no scans at all.
func demoServer(t *testing.T, seed bool) *httptest.Server {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if seed {
		if err := server.SeedDemo(t.Context(), st, time.Now().UTC().Truncate(time.Minute)); err != nil {
			t.Fatalf("seed demo: %v", err)
		}
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
		// A cold Chrome start on a shared runner can pass chromedp's 20 second default.
		chromedp.WSURLReadTimeout(chromeStartTimeout),
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

// awaitPromise makes an Evaluate wait for the promise its expression returns.
func awaitPromise(p *runtime.EvaluateParams) *runtime.EvaluateParams {
	return p.WithAwaitPromise(true)
}

// boot opens the dashboard with the welcome dismissed, waits for it to settle, and returns
// the route table's ids.
func boot(t *testing.T, ctx context.Context, ts *httptest.Server) []string {
	t.Helper()
	err := run(ctx, 30*time.Second,
		chromedp.Navigate(ts.URL+"/"),
		chromedp.Evaluate(`localStorage.setItem('fleetsweeper-welcome-dismissed', '1')`, nil),
		// A reload, not a hash change, so the first load's welcome splash cannot open over the
		// page and leave everything behind it inert.
		chromedp.Reload(),
		chromedp.Poll(settledJS, nil, chromedp.WithPollingTimeout(settleTimeout)),
	)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	var modals int
	if err := run(ctx, 5*time.Second, chromedp.Evaluate(`document.querySelectorAll('dialog[open]').length`, &modals)); err != nil || modals > 0 {
		t.Fatalf("boot: %d dialogs open over the dashboard (%v)", modals, err)
	}
	var routes []string
	err = run(ctx, 10*time.Second, chromedp.Evaluate(`import('/js/routes.js').then((m) => m.ROUTES.map((r) => r.id))`,
		&routes, awaitPromise))
	if err != nil || len(routes) == 0 {
		t.Fatalf("read route table: %v (%d routes)", err, len(routes))
	}
	return routes
}

// visit moves to the route's hash and waits for its view to settle, first running before
// so it can watch the render.
func visit(ctx context.Context, id, cluster, scanID string, before chromedp.Action) (string, error) {
	var hash string
	hashJS := fmt.Sprintf(`import('/js/router.js').then((m) => m.hashFor(%q, {cluster: %q, scanId: %q}))`, id, cluster, scanID)
	err := run(ctx, settleTimeout+10*time.Second,
		chromedp.Evaluate(hashJS, &hash, awaitPromise),
		before,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Setting the hash the page already shows fires no hashchange, so render directly.
			return chromedp.Evaluate(fmt.Sprintf(`((h) => {
  if (location.hash === h) import('/js/router.js').then((m) => m.render());
  else location.hash = h;
  return true;
})(%q)`, hash), nil).Do(ctx)
		}),
		chromedp.Sleep(50*time.Millisecond),
		chromedp.Poll(settledJS, nil, chromedp.WithPollingTimeout(settleTimeout)),
		chromedp.Sleep(300*time.Millisecond),
	)
	return hash, err
}

// shiftReport is what readShiftJS returns.
type shiftReport struct {
	// CLS is the layout shift score summed over the render.
	CLS float64 `json:"cls"`
	// Loading is the height of #ct while the skeleton showed, 0 when it never showed.
	Loading float64 `json:"loading"`
	// Loaded is the height of #ct once the view settled.
	Loaded float64 `json:"loaded"`
	// Gap is how far the loaded height within the first screen strayed from the skeleton's,
	// as a share of that screen, or -1 when the skeleton never showed.
	Gap float64 `json:"gap"`
}

// ringReport is what focusRingsJS returns.
type ringReport struct {
	// Checked counts the interactive elements focused.
	Checked int `json:"checked"`
	// Visible counts those that matched :focus-visible when focused.
	Visible int `json:"visible"`
	// Skipped describes each element that would not take focus.
	Skipped []string `json:"skipped"`
	// Bad describes each element whose focus ring is missing or too faint.
	Bad []string `json:"bad"`
}

// TestDashboardSmoke loads every route of the demo dashboard, fails on any console error or
// uncaught exception, checks each view settles into content or an empty state, and runs the
// scan trigger to its completion toast.
func TestDashboardSmoke(t *testing.T) {
	ts := demoServer(t, true)
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

	var kubeContexts []struct {
		Name string `json:"name"`
	}
	getJSON(t, ts.URL+"/api/contexts", &kubeContexts)

	routes := boot(t, ctx, ts)
	if errs := log.take(); len(errs) > 0 {
		t.Errorf("errors during boot:\n%s", strings.Join(errs, "\n"))
	}
	// A real key press puts Chrome's focus heuristic in keyboard mode, so the focus ring check
	// sees the rings a keyboard user sees.
	if err := run(ctx, 5*time.Second, chromedp.KeyEvent(kb.Tab)); err != nil {
		t.Fatalf("tab key: %v", err)
	}

	for _, id := range routes {
		log.setRoute(id)
		hash, err := visit(ctx, id, latestCluster, scans[0].ID, chromedp.Evaluate(watchShiftJS, nil))
		if err != nil {
			t.Errorf("route %s (%s): view never settled: %v", id, hash, err)
			continue
		}
		var state string
		var shift shiftReport
		var shot []byte
		rings := map[string]ringReport{}
		actions := make([]chromedp.Action, 0, 5)
		actions = append(actions,
			chromedp.Evaluate(viewStateJS, &state),
			chromedp.Evaluate(readShiftJS, &shift),
			chromedp.CaptureScreenshot(&shot),
		)
		for _, theme := range []string{"dark", "light"} {
			r := ringReport{}
			actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
				if err := chromedp.Evaluate(fmt.Sprintf(`(%s)(%q)`, focusRingsJS, theme), &r).Do(ctx); err != nil {
					return err
				}
				rings[theme] = r
				return nil
			}))
		}
		if err := run(ctx, 20*time.Second, actions...); err != nil {
			t.Errorf("route %s: inspect view: %v", id, err)
			continue
		}
		_ = os.WriteFile(filepath.Join(shots, id+".png"), shot, 0o600)
		t.Logf("route %-10s %-28s %-7s cls %.3f skeleton %4.0fpx content %5.0fpx gap %.2f rings %d",
			id, hash, state, shift.CLS, shift.Loading, shift.Loaded, shift.Gap, rings["dark"].Checked)
		if state != "content" && state != "empty" {
			t.Errorf("route %s (%s): view shows %s", id, hash, state)
		}
		if id == "manage" {
			var scanButtons int
			err := run(ctx, 5*time.Second, chromedp.Evaluate(
				`document.querySelectorAll('[data-action="scan-contexts"]').length`, &scanButtons))
			want := 0
			if len(kubeContexts) > 0 {
				want = len(kubeContexts) + 1
			}
			if err != nil {
				t.Errorf("route manage: count scan buttons: %v", err)
			} else if scanButtons != want {
				t.Errorf("route manage: %d scan buttons, want %d for %d contexts",
					scanButtons, want, len(kubeContexts))
			}
		}
		switch {
		case shift.CLS > maxShiftScore:
			t.Errorf("route %s: layout shift score %.3f, want at most %.2f", id, shift.CLS, maxShiftScore)
		case shift.Gap < 0:
			t.Errorf("route %s: no loading skeleton showed before the view", id)
		case shift.Gap > maxFillGap:
			t.Errorf("route %s: skeleton fills %.0fpx of the first screen, the view %.0fpx (gap %.2f, want at most %.2f)",
				id, shift.Loading, shift.Loaded, shift.Gap, maxFillGap)
		}
		for theme, r := range rings {
			focused := r.Checked - len(r.Skipped)
			if r.Visible < focused {
				t.Errorf("route %s (%s theme): %d of %d focused elements did not match :focus-visible, the check cannot see their rings",
					id, theme, focused-r.Visible, focused)
			}
			if len(r.Skipped) > 0 {
				t.Errorf("route %s (%s theme): %d visible interactive elements would not take focus:\n%s",
					id, theme, len(r.Skipped), strings.Join(r.Skipped[:min(len(r.Skipped), 5)], "\n"))
			}
			if len(r.Bad) > 0 {
				t.Errorf("route %s (%s theme): %d elements without a visible focus ring:\n%s", id, theme, len(r.Bad), strings.Join(r.Bad, "\n"))
			}
		}
		if errs := log.take(); len(errs) > 0 {
			t.Errorf("route %s: console errors:\n%s", id, strings.Join(errs, "\n"))
		}
	}

	t.Run("toast dedupe", func(t *testing.T) {
		var got []any
		err := run(ctx, 10*time.Second, chromedp.Evaluate(`import('/js/components/toast.js').then((m) => {
  m.toast('Dedupe check', 'info');
  m.toast('Dedupe check', 'info');
  m.toast('Keyed one', 'info', null, 'k');
  m.toast('Keyed two', 'info', null, 'k');
  const out = [document.querySelectorAll('.toast[data-key="Dedupe check"]').length,
    [...document.querySelectorAll('.toast[data-key="k"] .toast-msg')].map((e) => e.textContent).join(',')];
  document.querySelectorAll('.toast').forEach((e) => e.remove());
  return out;
})`, &got, awaitPromise))
		if err != nil {
			t.Fatalf("toast dedupe: %v", err)
		}
		if diff := cmp.Diff([]any{float64(1), "Keyed two"}, got); diff != "" {
			t.Errorf("toasts mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("read error message", func(t *testing.T) {
		var got string
		err := run(ctx, 10*time.Second, chromedp.Evaluate(
			`import('/js/api.js').then((m) => m.api('/scans/nope/report')).catch((e) => e.message)`,
			&got, awaitPromise))
		if err != nil {
			t.Fatalf("read error message: %v", err)
		}
		if diff := cmp.Diff("scan not found", got); diff != "" {
			t.Errorf("error message mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("outliers held", func(t *testing.T) {
		var resp struct {
			Outliers []struct {
				ExplainedBy string `json:"explained_by"`
			} `json:"outliers"`
		}
		getJSON(t, ts.URL+"/api/outliers", &resp)
		var cohortResp struct {
			Cohorts []struct {
				Outliers []struct {
					Scope string `json:"scope"`
				} `json:"outliers"`
			} `json:"cohorts"`
		}
		getJSON(t, ts.URL+"/api/cohorts", &cohortResp)
		open := 0
		for _, o := range resp.Outliers {
			if o.ExplainedBy == "" {
				open++
			}
		}
		fleetOpen := open
		wantScopes := map[string]int{}
		for _, c := range cohortResp.Cohorts {
			for _, o := range c.Outliers {
				wantScopes[o.Scope]++
				open++
			}
		}
		if len(wantScopes) == 0 {
			t.Fatalf("demo has no cohort outliers to assert on")
		}
		held := len(resp.Outliers) - fleetOpen
		var rows int
		var summary string
		var scopeCells []string
		err := run(ctx, settleTimeout+5*time.Second,
			chromedp.Evaluate(`location.hash = '#/outliers'`, nil),
			chromedp.Poll(settledJS+` && !!document.querySelector('#outlierStrips')`,
				nil, chromedp.WithPollingTimeout(settleTimeout)),
			chromedp.Evaluate(`document.querySelectorAll('#outlierTable tbody tr').length`, &rows),
			chromedp.Evaluate(`[...document.querySelectorAll('#outlierTable tbody tr')]
				.map((r) => r.cells[3].textContent).filter((s) => s !== 'fleet')`, &scopeCells),
			chromedp.Evaluate(`(document.querySelector('#outlierHeld summary') || {textContent: ''}).textContent`, &summary),
		)
		if err != nil {
			t.Fatalf("outliers held: %v", err)
		}
		if rows != open {
			t.Errorf("open outlier rows: %d != %d", rows, open)
		}
		gotScopes := map[string]int{}
		for _, s := range scopeCells {
			gotScopes[s]++
		}
		if diff := cmp.Diff(wantScopes, gotScopes); diff != "" {
			t.Errorf("cohort rows by norm scope mismatch (-want +got):\n%s", diff)
		}
		if want := fmt.Sprintf("%d ", held); !strings.HasPrefix(summary, want) {
			t.Errorf("held summary %q does not begin with %q", summary, want)
		}
		t.Logf("open %d held %d total %d", open, held, len(resp.Outliers))
	})

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

// emptySentence matches an empty state that opens with a capitalized sentence ending in a
// period.
var emptySentence = regexp.MustCompile(`^[A-Z][^\n]*?\.(\s|$)`) //nolint:gochecknoglobals // Not modified, simplifies testing.

// TestDashboardEmpty loads every route of a demo server whose store holds no scans and checks
// each view explains its emptiness in a sentence instead of erroring or showing nothing.
func TestDashboardEmpty(t *testing.T) {
	ts := demoServer(t, false)
	ctx := newBrowser(t)
	log := &consoleLog{route: "boot"}
	log.listen(ctx)
	routes := boot(t, ctx, ts)
	for _, id := range routes {
		log.setRoute(id)
		hash, err := visit(ctx, id, "no-such-cluster", "no-such-scan", chromedp.ActionFunc(func(context.Context) error { return nil }))
		if err != nil {
			t.Errorf("route %s (%s): view never settled: %v", id, hash, err)
			continue
		}
		var text string
		if err := run(ctx, 5*time.Second, chromedp.Evaluate(emptyTextJS, &text)); err != nil {
			t.Errorf("route %s: read empty state: %v", id, err)
			continue
		}
		t.Logf("route %-10s %q", id, text)
		switch {
		case text == "":
			t.Errorf("route %s (%s): no [data-empty] state on an empty store", id, hash)
		case !emptySentence.MatchString(text):
			t.Errorf("route %s: empty state %q is not a capitalized sentence ending in a period", id, text)
		}
		if errs := log.take(); len(errs) > 0 {
			t.Errorf("route %s: console errors:\n%s", id, strings.Join(errs, "\n"))
		}
	}
}
