package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEventBusFanOut verifies a subscriber receives a published event.
func TestEventBusFanOut(t *testing.T) {
	t.Parallel()
	bus := newEventBus()
	ch, unsub := bus.subscribe(4)
	defer unsub()

	bus.publish(Event{Type: "scan.complete", At: time.Now(), Payload: map[string]any{"score": 88}})
	select {
	case ev := <-ch:
		if ev.Type != "scan.complete" {
			t.Errorf("type: want scan.complete, got %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive event within 1s")
	}
}

// TestEventBusDropOnOverflow verifies a slow subscriber does not block
// fan-out: when its buffer is full, additional events drop silently while
// the buffered event is still delivered and other subscribers still receive.
func TestEventBusDropOnOverflow(t *testing.T) {
	t.Parallel()
	bus := newEventBus()
	slow, unsubSlow := bus.subscribe(1)
	defer unsubSlow()
	fast, unsubFast := bus.subscribe(4)
	defer unsubFast()

	published := make(chan struct{})
	go func() {
		bus.publish(Event{Type: "first"})
		bus.publish(Event{Type: "second"})
		close(published)
	}()
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("publish blocked on a full subscriber")
	}

	if ev := <-slow; ev.Type != "first" {
		t.Errorf("slow subscriber: want first, got %s", ev.Type)
	}
	select {
	case ev := <-slow:
		t.Errorf("slow subscriber: overflow event should drop, got %s", ev.Type)
	default:
	}
	for _, want := range []string{"first", "second"} {
		select {
		case ev := <-fast:
			if ev.Type != want {
				t.Errorf("fast subscriber: want %s, got %s", want, ev.Type)
			}
		case <-time.After(time.Second):
			t.Fatalf("fast subscriber: %s not delivered within 1s", want)
		}
	}
}

// sseEventNames reads an SSE stream and sends each event name on the returned channel until the
// stream ends, then closes the channel.
func sseEventNames(body io.Reader) <-chan string {
	out := make(chan string, 8)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(body)
		for sc.Scan() {
			if name, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				out <- name
			}
		}
	}()
	return out
}

// TestEventsStreamThroughHandlerChain verifies the SSE endpoint streams through the full
// production chain (request logging, CORS, rate limiting, auth, audit) and that the stream
// outlives the server's WriteTimeout because the handler clears its write deadline.
func TestEventsStreamThroughHandlerChain(t *testing.T) {
	t.Parallel()
	srv := newRateLimitedTestServer(t, 600, 60)
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Config.WriteTimeout = 300 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200, got %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("content type: want text/event-stream, got %q", got)
	}

	names := sseEventNames(resp.Body)
	next := func(want string) {
		t.Helper()
		select {
		case got, ok := <-names:
			if !ok {
				t.Fatalf("stream ended before %s", want)
			}
			if got != want {
				t.Fatalf("want event %s, got %s", want, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no %s event within 2s", want)
		}
	}
	next("stream.hello")

	time.Sleep(2 * ts.Config.WriteTimeout)
	srv.PublishEvent(EventScanComplete, map[string]any{"scan_id": "s-1"})
	next(EventScanComplete)
}

// noFlushWriter is a ResponseWriter that cannot flush, standing in for a wrapper that hides
// the connection's flusher.
type noFlushWriter struct {
	// header is the response header map.
	header http.Header
	// status is the written status code.
	status int
}

// Header returns the header map.
func (w *noFlushWriter) Header() http.Header { return w.header }

// Write discards the body.
func (w *noFlushWriter) Write(p []byte) (int, error) { return len(p), nil }

// WriteHeader records the status.
func (w *noFlushWriter) WriteHeader(code int) { w.status = code }

// TestEventsStreamWithoutFlusher verifies the SSE endpoint answers 500 rather than a stream that
// never delivers when the writer cannot flush.
func TestEventsStreamWithoutFlusher(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	w := &noFlushWriter{header: http.Header{}}
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	srv.handleEventsStream(w, req)
	if w.status != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", w.status)
	}
	if got := w.header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("error content type: want JSON, got %q", got)
	}
}

// TestEventsStreamSendsHello verifies the SSE endpoint emits the hello
// event and respects context cancellation.
func TestEventsStreamSendsHello(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		srv.mux.ServeHTTP(rec, req)
		close(done)
	}()

	// Wait briefly for the hello to land, then cancel to release the handler.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.Body(), "stream.hello") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit after cancel")
	}
	if got := rec.Body(); !strings.Contains(got, "stream.hello") {
		t.Fatalf("missing hello event in body: %q", got)
	}
}
