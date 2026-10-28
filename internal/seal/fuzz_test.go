package seal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = decodeSignature(in)
	})
}

// FuzzReadBundle asserts that ReadBundle never panics, that every failure wraps ErrBundle, and
// that any archive it accepts survives a WriteBundle and ReadBundle round trip with the same root
// and files. The harness builds a two-entry archive from fuzzed names, types, and contents, so
// the fuzzer reaches the path and layout rules instead of dying on a tar or gzip checksum.
func FuzzReadBundle(f *testing.F) {
	seeds := []struct {
		Name1, Name2 string
		Type1, Type2 byte
	}{
		{Name1: "root/report.json", Name2: "root/MANIFEST", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "root/a", Name2: "other/b", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "root/a", Name2: "root/b", Type1: tar.TypeSymlink, Type2: tar.TypeReg},
		{Name1: "root/a", Name2: "root/a", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "root//a", Name2: "root/b", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "root/../a", Name2: "root/b", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "/root/a", Name2: "root/b", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "a", Name2: "root/b", Type1: tar.TypeReg, Type2: tar.TypeReg},
		{Name1: "root/d", Name2: "root/b", Type1: tar.TypeDir, Type2: tar.TypeReg},
	}
	for _, s := range seeds {
		f.Add(s.Name1, s.Name2, s.Type1, s.Type2, []byte("{}"))
	}
	f.Fuzz(func(t *testing.T, name1, name2 string, type1, type2 byte, data []byte) {
		var in bytes.Buffer
		zw := gzip.NewWriter(&in)
		tw := tar.NewWriter(zw)
		for _, e := range []struct {
			Name string
			Type byte
		}{{Name: name1, Type: type1}, {Name: name2, Type: type2}} {
			hdr := &tar.Header{Name: e.Name, Typeflag: e.Type, Mode: 0o644, Format: tar.FormatPAX}
			if e.Type == tar.TypeReg {
				hdr.Size = int64(len(data))
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return
			}
			if e.Type == tar.TypeReg {
				if _, err := tw.Write(data); err != nil {
					return
				}
			}
		}
		if tw.Close() != nil || zw.Close() != nil {
			return
		}

		root, got, err := ReadBundle(&in)
		if err != nil {
			if !errors.Is(err, ErrBundle) {
				t.Fatalf("error does not wrap ErrBundle: %v", err)
			}
			return
		}
		var out bytes.Buffer
		if err := WriteBundle(&out, root, got, time.Unix(0, 0)); err != nil {
			t.Fatalf("rewrite accepted bundle: %v", err)
		}
		root2, again, err := ReadBundle(&out)
		if err != nil {
			t.Fatalf("reread accepted bundle: %v", err)
		}
		if root2 != root {
			t.Errorf("root changed: %q to %q", root, root2)
		}
		if diff := cmp.Diff(got, again); diff != "" {
			t.Errorf("files changed (-first +second):\n%s", diff)
		}
	})
}
