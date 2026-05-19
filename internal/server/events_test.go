package server

import (
	"context"
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
// fan-out: when its buffer is full, additional events drop silently.
func TestEventBusDropOnOverflow(t *testing.T) {
	t.Parallel()
	bus := newEventBus()
	_, unsub := bus.subscribe(1)
	defer unsub()

	// Fill the buffer plus an overflow event. Neither call should block.
	bus.publish(Event{Type: "first"})
	bus.publish(Event{Type: "second"})
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
		if strings.Contains(rec.body.String(), "stream.hello") {
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
	if !strings.Contains(rec.body.String(), "stream.hello") {
		t.Fatalf("missing hello event in body: %q", rec.body.String())
	}
}
