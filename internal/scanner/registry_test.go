package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	stub := ScannerFunc(func(_ context.Context, _ *kube.Client) (Result, error) {
		return Result{Scanner: "stub"}, nil
	})

	t.Run("register and get", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.Register("test", stub)
		got, ok := r.Get("test")
		if !ok {
			t.Fatal("expected scanner to be found")
		}
		if got == nil {
			t.Fatal("expected non-nil scanner")
		}
	})

	t.Run("get missing", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		_, ok := r.Get("nonexistent")
		if ok {
			t.Fatal("expected scanner not found")
		}
	})

	t.Run("names sorted", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.Register("zebra", stub)
		r.Register("alpha", stub)
		r.Register("middle", stub)
		want := []string{"alpha", "middle", "zebra"}
		got := r.Names()
		if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("duplicate panics", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.Register("dup", stub)
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic on duplicate registration")
			}
		}()
		r.Register("dup", stub)
	})

	t.Run("all returns copy", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.Register("one", stub)
		all := r.All()
		if len(all) != 1 {
			t.Fatalf("expected 1 scanner, got %d", len(all))
		}
		all["injected"] = stub
		if _, ok := r.Get("injected"); ok {
			t.Fatal("modifying All() result should not affect registry")
		}
	})
}

func TestScannerFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantResult Result
		Want       error
	}{{ // Test 0: Successful scan.
		WantResult: Result{Scanner: "test", Data: "hello"},
		Want:       nil,
	}, { // Test 1: Error scan.
		WantResult: Result{},
		Want:       fmt.Errorf("boom"),
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			f := ScannerFunc(func(_ context.Context, _ *kube.Client) (Result, error) {
				return test.WantResult, test.Want
			})
			got, err := f.Scan(context.Background(), nil)
			if diff := cmp.Diff(test.Want, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("error mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantResult.Scanner, got.Scanner); diff != "" {
				t.Errorf("scanner mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
