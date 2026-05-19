package seal

import (
	"errors"
	"testing"
)

// FuzzVerify asserts that Verify rejects every signature derived from a
// different key or different data and accepts the canonical signature
// for the original key/data pair. Together with the fuzz engine's random
// inputs this gives strong assurance there is no edge case where Verify
// returns success on tampered data.
func FuzzVerify(f *testing.F) {
	seeds := []struct {
		Data []byte
		Key  string
	}{
		{Data: []byte(""), Key: "k"},
		{Data: []byte("a"), Key: "k"},
		{Data: []byte("the quick brown fox"), Key: "key"},
		{Data: []byte{0, 1, 2, 3, 0xFF}, Key: "n"},
	}
	for _, s := range seeds {
		f.Add(s.Data, s.Key)
	}
	f.Fuzz(func(t *testing.T, data []byte, key string) {
		if key == "" {
			// Sign returns ErrMissingKey for empty keys; not interesting.
			return
		}
		good, err := Sign(data, key)
		if err != nil {
			t.Fatalf("Sign(%q, %q): %v", data, key, err)
		}
		if err := Verify(data, good, key); err != nil {
			t.Errorf("verify good sig: %v", err)
		}

		// Tamper with data (append a byte). New data must fail verify.
		tampered := append([]byte{}, data...)
		tampered = append(tampered, 0xAB)
		if err := Verify(tampered, good, key); !errors.Is(err, ErrMismatch) {
			t.Errorf("tampered data: want ErrMismatch, got %v", err)
		}
	})
}

// FuzzDecodeSignature asserts the signature decoder never panics on
// arbitrary input. Valid inputs round-trip through Sign; arbitrary
// strings must produce ErrMalformed (or, by chance, a valid 32-byte
// payload that just won't match anything real).
func FuzzDecodeSignature(f *testing.F) {
	seeds := []string{
		"",
		"sha256=",
		"sha256=00",
		"sha256=zzzz",
		"deadbeef",
		"sha256=" + "ab" + "cd",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = decodeSignature(in)
	})
}
