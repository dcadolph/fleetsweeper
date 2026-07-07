package server

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzAlertManagerPayload asserts the AlertManager webhook decoder plus the
// record builder never panic on arbitrary request bodies. It mirrors the
// handler's parse path (json.Unmarshal into alertManagerPayload, then
// buildAlertRecord per alert) without a store, so any panic in the decode or
// label-merging logic surfaces deterministically. Bodies that fail to decode
// are the handler's 400 path and are not interesting here.
func FuzzAlertManagerPayload(f *testing.F) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seeds := []string{
		`{}`,
		`{"version":"4","status":"firing","alerts":[]}`,
		`{"version":"4","alerts":[{"status":"firing","labels":{"alertname":"X","cluster":"c","severity":"warning"},"annotations":{"summary":"s"},"fingerprint":"abc"}]}`,
		`{"version":"4","commonLabels":{"cluster":"c"},"commonAnnotations":{"summary":"g"},"alerts":[{"labels":{"alertname":"Y"}}]}`,
		`{"alerts":[{"startsAt":"2026-01-01T00:00:00Z","endsAt":"2026-01-02T00:00:00Z"}]}`,
		`{"alerts":[{},{},{}]}`,
		`{"alerts":null}`,
		`not json`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var payload alertManagerPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return
		}
		for _, a := range payload.Alerts {
			rec := buildAlertRecord(a, payload.CommonLabels, payload.CommonAnnotations, now)
			// mergeStringMaps must always return non-nil maps so downstream
			// store writes and label lookups never nil-panic.
			if rec.Labels == nil || rec.Annotations == nil {
				t.Errorf("buildAlertRecord produced nil map: labels=%v ann=%v",
					rec.Labels, rec.Annotations)
			}
		}
	})
}

// FuzzFalcoEvent asserts the Falco webhook decoder plus buildFalcoAlert never
// panic on arbitrary request bodies. output_fields carries mixed-type values
// that stringifyFalcoFields must coerce without crashing, and every event must
// yield a non-empty fingerprint and a non-nil labels map.
func FuzzFalcoEvent(f *testing.F) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seeds := []string{
		`{}`,
		`{"rule":"R","priority":"Critical","output":"o"}`,
		`{"rule":"R","output_fields":{"k8s.pod.name":"p","container.id":"c","n":42,"b":true,"nested":{"a":1},"nul":null}}`,
		`{"rule":"R","tags":["a","b"],"source":"syscall","hostname":"n1"}`,
		`{"rule":"R","time":"2026-01-01T00:00:00Z"}`,
		`{"output_fields":{"cluster":"c"}}`,
		`{"output_fields":null}`,
		`not json`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var ev falcoEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			return
		}
		rec := buildFalcoAlert(ev, "", now)
		if rec.Fingerprint == "" {
			t.Error("buildFalcoAlert produced an empty fingerprint")
		}
		if rec.Labels == nil {
			t.Error("buildFalcoAlert produced a nil labels map")
		}
	})
}
