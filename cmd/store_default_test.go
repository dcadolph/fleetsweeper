package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveDBPathDefault verifies an empty --db resolves to the default state store, creates
// it private to the user, and announces the path on first use only.
func TestResolveDBPathDefault(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	want := filepath.Join(state, "fleetsweeper", "fleet.db")

	var first bytes.Buffer
	cmd := newStoreCmd("")
	cmd.SetErr(&first)
	got, err := resolveDBPath(cmd)
	if err != nil || got != want {
		t.Fatalf("resolve: got %q, %v, want %q", got, err, want)
	}
	if n := strings.Count(first.String(), want); n != 1 {
		t.Errorf("first use: path printed %d times, want 1: %q", n, first.String())
	}
	info, err := os.Stat(want)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("store file: %v, mode %v, want 0600", err, info)
	}
	dirInfo, err := os.Stat(filepath.Dir(want))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("store dir: %v, mode %v, want 0700", err, dirInfo)
	}

	var second bytes.Buffer
	cmd = newStoreCmd("")
	cmd.SetErr(&second)
	if _, err := resolveDBPath(cmd); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.Len() != 0 {
		t.Errorf("second use printed %q, want nothing", second.String())
	}
}

// TestResolveDBPathExplicit verifies --db wins over the default and creates nothing.
func TestResolveDBPathExplicit(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	explicit := filepath.Join(t.TempDir(), "mine.db")
	got, err := resolveDBPath(newStoreCmd(explicit))
	if err != nil || got != explicit {
		t.Fatalf("resolve: got %q, %v, want %q", got, err, explicit)
	}
	if _, err := os.Stat(filepath.Join(state, "fleetsweeper")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("explicit --db created the default state dir: %v", err)
	}
}

// TestResolveDBPathNoHome verifies a process with no home and no XDG_STATE_HOME has no store.
func TestResolveDBPathNoHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")
	if _, err := resolveDBPath(newStoreCmd("")); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("want ErrNoDatabase, got %v", err)
	}
}

// TestScanAndServeShareDefaultStore verifies a scan with no --db persists to the default store
// and serve with no --db opens that same store.
func TestScanAndServeShareDefaultStore(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "config")
	if err := os.WriteFile(kubeconfig, []byte(unreachableKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	if err := execScanCmd(t, "scan", "--kubeconfig="+kubeconfig, "--db=", "--group=", "--contexts=",
		"--scanners=version", "--html-file="+filepath.Join(dir, "report.html")); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "fleetsweeper", "fleet.db")); err != nil {
		t.Fatalf("default store not written: %v", err)
	}

	st, err := openServeStore(newStoreCmd(""), false)
	if err != nil {
		t.Fatalf("serve store: %v", err)
	}
	defer st.Close()
	scans, err := st.ListScans(context.Background(), 5)
	if err != nil || len(scans) != 1 {
		t.Fatalf("serve sees %d scans, %v; want the 1 scan run wrote", len(scans), err)
	}
}
