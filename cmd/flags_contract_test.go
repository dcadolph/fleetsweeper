package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagRead is a flag name read through a Flags().Get* or PersistentFlags().Get* call.
type flagRead struct {
	// Name is the flag name passed to the Get call.
	Name string
	// Pos is the file:line of the Get call.
	Pos string
}

// flagsContractAllowed lists flag names cobra defines lazily and so never appear in the walk.
var flagsContractAllowed = map[string]bool{"help": true}

// collectFlagReads parses the non-test Go files in dir and returns every string-literal flag
// name passed to a Get* method on a Flags() or PersistentFlags() call.
func collectFlagReads(t *testing.T, dir string) []flagRead {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	var reads []flagRead
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "Get") {
				return true
			}
			recv, ok := sel.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			recvSel, ok := recv.Fun.(*ast.SelectorExpr)
			if !ok || (recvSel.Sel.Name != "Flags" && recvSel.Sel.Name != "PersistentFlags") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			pos := fset.Position(call.Pos())
			reads = append(reads, flagRead{
				Name: name,
				Pos:  fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line),
			})
			return true
		})
	}
	return reads
}

// collectDefinedFlags walks cmd and its subcommands and returns every defined flag name and
// the subset defined locally without persistence. It skips the completion command, which cobra
// adds on first execution with flags it reads itself, so the result does not depend on whether
// another test has already run the command tree.
func collectDefinedFlags(cmd *cobra.Command, all, local map[string]bool) {
	if cmd.Name() == "completion" {
		return
	}
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) { all[f.Name] = true })
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		all[f.Name] = true
		local[f.Name] = true
	})
	for _, sub := range cmd.Commands() {
		collectDefinedFlags(sub, all, local)
	}
}

// flagsContractProblems returns the sorted contract violations for the given reads and
// definitions.
func flagsContractProblems(reads []flagRead, all, local map[string]bool) []string {
	var problems []string
	read := make(map[string]bool, len(reads))
	for _, r := range reads {
		read[r.Name] = true
		if !all[r.Name] && !flagsContractAllowed[r.Name] {
			problems = append(problems, fmt.Sprintf("%s: flag %q is read but never defined",
				r.Pos, r.Name))
		}
	}
	for name := range local {
		if !read[name] && !flagsContractAllowed[name] {
			problems = append(problems, fmt.Sprintf("flag %q is defined but never read", name))
		}
	}
	sort.Strings(problems)
	return problems
}

// TestFlagsDefinedAndRead verifies every flag read in cmd exists and every local flag is read.
func TestFlagsDefinedAndRead(t *testing.T) {
	t.Parallel()
	all := map[string]bool{}
	local := map[string]bool{}
	// Commands sorts its slice in place, so the walk holds the lock like every Execute.
	func() {
		defer lockRootCmd(t)()
		collectDefinedFlags(rootCmd, all, local)
	}()
	reads := collectFlagReads(t, ".")
	if len(reads) == 0 || len(all) == 0 {
		t.Fatalf("empty fixture: %d reads, %d defined flags", len(reads), len(all))
	}
	if diff := cmp.Diff([]string(nil), flagsContractProblems(reads, all, local),
		cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("flag contract mismatch (-want +got):\n%s", diff)
	}
}

// TestFlagsContractProblems verifies the violation detection on synthetic input.
func TestFlagsContractProblems(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Reads  []flagRead
		All    map[string]bool
		Local  map[string]bool
		WantIn []string
	}{
		{ // Test 0: Everything matches.
			Reads: []flagRead{{Name: "a", Pos: "x.go:1"}},
			All:   map[string]bool{"a": true}, Local: map[string]bool{"a": true},
		},
		{ // Test 1: Read but undefined.
			Reads:  []flagRead{{Name: "b", Pos: "x.go:2"}},
			All:    map[string]bool{},
			Local:  map[string]bool{},
			WantIn: []string{`x.go:2: flag "b" is read but never defined`},
		},
		{ // Test 2: Defined locally but never read.
			All: map[string]bool{"c": true}, Local: map[string]bool{"c": true},
			WantIn: []string{`flag "c" is defined but never read`},
		},
		{ // Test 3: Help is allowed.
			Reads: []flagRead{{Name: "help", Pos: "x.go:3"}},
			All:   map[string]bool{}, Local: map[string]bool{},
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := flagsContractProblems(test.Reads, test.All, test.Local)
			if diff := cmp.Diff(test.WantIn, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
