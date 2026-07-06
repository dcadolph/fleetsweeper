package seal

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSign_RoundTrip(t *testing.T) {
	t.Parallel()
	data := []byte(`{"hello":"world"}`)
	sig, err := Sign(data, "topsecret")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.HasPrefix(sig, Prefix) {
		t.Errorf("missing prefix: %s", sig)
	}
	if err := Verify(data, sig, "topsecret"); err != nil {
		t.Errorf("verify round-trip: %v", err)
	}
}

func TestSign_MissingKey(t *testing.T) {
	t.Parallel()
	if _, err := Sign([]byte("x"), ""); !errors.Is(err, ErrMissingKey) {
		t.Errorf("want ErrMissingKey, got %v", err)
	}
}

func TestVerify_MissingKey(t *testing.T) {
	t.Parallel()
	sig, _ := Sign([]byte("x"), "k")
	if err := Verify([]byte("x"), sig, ""); !errors.Is(err, ErrMissingKey) {
		t.Errorf("want ErrMissingKey, got %v", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		In   string
	}{
		{Name: "empty", In: ""},
		{Name: "no_prefix", In: "deadbeef"},
		{Name: "bad_hex", In: "sha256=not-hex"},
		{Name: "too_short", In: "sha256=deadbeef"},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			if err := Verify([]byte("x"), tc.In, "k"); !errors.Is(err, ErrMalformed) {
				t.Errorf("want ErrMalformed, got %v", err)
			}
		})
	}
}

func TestVerify_Mismatch(t *testing.T) {
	t.Parallel()
	sig, _ := Sign([]byte("original"), "k")
	if err := Verify([]byte("tampered"), sig, "k"); !errors.Is(err, ErrMismatch) {
		t.Errorf("want ErrMismatch, got %v", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	t.Parallel()
	sig, _ := Sign([]byte("data"), "real")
	if err := Verify([]byte("data"), sig, "imposter"); !errors.Is(err, ErrMismatch) {
		t.Errorf("want ErrMismatch, got %v", err)
	}
}

func TestSignReader_MatchesSign(t *testing.T) {
	t.Parallel()
	data := []byte("the quick brown fox")
	want, _ := Sign(data, "k")
	got, err := SignReader(bytes.NewReader(data), "k")
	if err != nil {
		t.Fatalf("sign reader: %v", err)
	}
	if got != want {
		t.Errorf("streaming sign mismatch: got %s want %s", got, want)
	}
}

func TestVerifyReader_RoundTrip(t *testing.T) {
	t.Parallel()
	data := []byte("payload bytes")
	sig, _ := Sign(data, "k")
	if err := VerifyReader(bytes.NewReader(data), sig, "k"); err != nil {
		t.Errorf("verify reader: %v", err)
	}
}

func TestVerifyReader_Tampered(t *testing.T) {
	t.Parallel()
	sig, _ := Sign([]byte("original"), "k")
	if err := VerifyReader(bytes.NewReader([]byte("tampered")), sig, "k"); !errors.Is(err, ErrMismatch) {
		t.Errorf("want ErrMismatch, got %v", err)
	}
}

func TestSign_DifferentKeysProduceDifferentSeals(t *testing.T) {
	t.Parallel()
	a, _ := Sign([]byte("x"), "key-a")
	b, _ := Sign([]byte("x"), "key-b")
	if a == b {
		t.Errorf("expected different seals for different keys; both = %s", a)
	}
}
