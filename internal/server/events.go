package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Event is one server-sent event the dashboard or external consumers
// subscribe to. The Type field is the SSE event name; Data is JSON-
// serialized on the wire.
type Event struct {
	// Type categorises the event (for example "scan.complete").
	Type string `json:"type"`
	// At is when the event was emitted.
	At time.Time `json:"at"`
	// Payload is the event-specific data.
	Payload any `json:"payload,omitempty"`
}

// Event type constants. New event types must follow `<noun>.<verb>` so
// consumers can subscribe by prefix.
const (
	// EventScanComplete fires once after each scan persists.
	EventScanComplete = "scan.complete"
	// EventScanFailed fires when a triggered scan errored out.
	EventScanFailed = "scan.failed"
	// EventKeyRevoked fires when an admin revokes an API key.
	EventKeyRevoked = "key.revoked"
	// EventAlertReceived fires for each alert delivered by AlertManager.
	EventAlertReceived = "alert.received"
)

// eventBus fans out Event values to every subscribed channel. Subscribers
// that fail to keep up have their slot dropped; the bus itself never
// blocks the producer.
type eventBus struct {
	mu      sync.Mutex
	nextID  atomic.Int64
	streams map[int64]chan Event
}

// newEventBus constructs an empty event bus.
func newEventBus() *eventBus {
	return &eventBus{streams: make(map[int64]chan Event)}
}

// subscribe registers a new consumer and returns the channel plus an
// unsubscribe function the caller must invoke when done.
func (b *eventBus) subscribe(buffer int) (<-chan Event, func()) {
	ch := make(chan Event, buffer)
	id := b.nextID.Add(1)
	b.mu.Lock()
	b.streams[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.streams, id)
		b.mu.Unlock()
		close(ch)
	}
}

// publish delivers e to every subscriber. Subscribers with full buffers
// have the event dropped so a slow client cannot block fan-out.
func (b *eventBus) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.streams {
		select {
		case ch <- e:
		default:
			// drop on overflow; consumers must drain.
		}
	}
}

// PublishEvent is the server-facing API for emitting events. Other handlers
// call it after persisting a scan or revoking a key.
func (s *Server) PublishEvent(typ string, payload any) {
	if s.events == nil {
		return
	}
	s.events.publish(Event{Type: typ, At: time.Now().UTC(), Payload: payload})
}

// handleEventsStream is the SSE endpoint at /api/events. It keeps the
// connection open and writes one event per scan completion or key change
// until either side closes.
//
// The server's WriteTimeout would cut the stream off, so the handler clears the write deadline
// through http.ResponseController, which reaches the connection through every middleware
// wrapper's Unwrap method.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log.Debug("events: clear write deadline", zap.Error(err))
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if err := rc.Flush(); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	ch, unsub := s.events.subscribe(16)
	defer unsub()

	// Send a "hello" event immediately so clients confirm the stream is
	// live before any real event fires.
	if err := writeSSE(w, Event{Type: "stream.hello", At: time.Now().UTC()}); err != nil {
		s.log.Debug("events: hello write failed", zap.Error(err))
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// writeSSE marshals an event into the SSE wire format and writes it to w.
func writeSSE(w http.ResponseWriter, ev Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
	return err
}
