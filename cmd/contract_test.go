package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cliDocPath is the CLI reference every command must appear in.
const cliDocPath = "../docs/reference/cli.md"

// contractCommands returns every user-facing command under root, depth first, skipping the
// help and completion commands cobra adds.
func contractCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, c := range root.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		out = append(out, c)
		out = append(out, contractCommands(c)...)
	}
	return out
}

// commandPath returns the command path without the binary name, e.g. "group create".
func commandPath(c *cobra.Command) string {
	return strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")
}

// sentenceProblem returns why s is not a sentence that starts with a capital and ends with a
// period, or an empty string when it is.
func sentenceProblem(s string) string {
	switch {
	case s == "":
		return "is empty"
	case !unicode.IsUpper([]rune(s)[0]):
		return fmt.Sprintf("%q does not start with a capital", s)
	case !strings.HasSuffix(s, "."):
		return fmt.Sprintf("%q does not end with a period", s)
	}
	return ""
}

// messageProblem returns why msg is not shaped like a user-facing error, or an empty string
// when it is. Errors are lowercase, colon-separated, and never end with a period. A message
// may open with a flag name or a format verb, which carry their own case.
func messageProblem(msg string) string {
	switch {
	case msg == "":
		return "is empty"
	case unicode.IsUpper([]rune(msg)[0]) && !strings.HasPrefix(msg, "%"):
		return fmt.Sprintf("%q starts with a capital", msg)
	case strings.HasSuffix(msg, "."):
		return fmt.Sprintf("%q ends with a period", msg)
	}
	return ""
}

// exampleProblems returns every example line of c that does not resolve to c or one of its
// subcommands, or that uses a flag the resolved command does not define.
func exampleProblems(c *cobra.Command) []string {
	var problems []string
	for _, line := range strings.Split(c.Example, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != rootCmd.Name() {
			problems = append(problems, fmt.Sprintf("%q does not start with %s", line, rootCmd.Name()))
			continue
		}
		found, _, err := rootCmd.Find(fields[1:])
		if err != nil || !isWithin(found, c) {
			problems = append(problems, fmt.Sprintf("%q does not run %q", line, commandPath(c)))
			continue
		}
		for _, f := range fields[1:] {
			name, short := "", ""
			switch {
			case strings.HasPrefix(f, "--"):
				name, _, _ = strings.Cut(strings.TrimPrefix(f, "--"), "=")
			case strings.HasPrefix(f, "-") && len(f) == 2:
				short = f[1:]
			default:
				continue
			}
			if name != "" && found.Flags().Lookup(name) == nil && found.InheritedFlags().Lookup(name) == nil {
				problems = append(problems, fmt.Sprintf("%q uses unknown flag --%s", line, name))
			}
			if short != "" && found.Flags().ShorthandLookup(short) == nil {
				problems = append(problems, fmt.Sprintf("%q uses unknown flag -%s", line, short))
			}
		}
	}
	return problems
}

// isWithin reports whether c is ancestor or one of its subcommands.
func isWithin(c, ancestor *cobra.Command) bool {
	for ; c != nil; c = c.Parent() {
		if c == ancestor {
			return true
		}
	}
	return false
}

func TestCommandContract(t *testing.T) {
	t.Parallel()
	defer lockRootCmd(t)()
	doc, err := os.ReadFile(cliDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", cliDocPath, err)
	}
	flagTypes := map[string]string{}
	flagOwner := map[string]string{}
	for _, c := range append([]*cobra.Command{rootCmd}, contractCommands(rootCmd)...) {
		path := commandPath(c)
		if p := sentenceProblem(c.Short); p != "" {
			t.Errorf("command %q: Short %s", path, p)
		}
		if c != rootCmd && strings.TrimSpace(c.Example) == "" {
			t.Errorf("command %q: no Example", path)
		}
		for _, problem := range exampleProblems(c) {
			t.Errorf("command %q: example %s", path, problem)
		}
		if c != rootCmd && !strings.Contains(string(doc), "| `"+path+"` |") {
			t.Errorf("command %q: missing from %s", path, cliDocPath)
		}
		visit := func(f *pflag.Flag) {
			if f.Hidden || f.Name == "help" {
				return
			}
			if p := sentenceProblem(f.Usage); p != "" {
				t.Errorf("command %q: flag --%s usage %s", path, f.Name, p)
			}
			typ := f.Value.Type()
			if prev, ok := flagTypes[f.Name]; ok && prev != typ {
				t.Errorf("flag --%s is %s on %q and %s on %q", f.Name, typ, path, prev, flagOwner[f.Name])
			}
			if _, ok := flagTypes[f.Name]; !ok {
				flagTypes[f.Name], flagOwner[f.Name] = typ, path
			}
		}
		c.LocalNonPersistentFlags().VisitAll(visit)
		c.PersistentFlags().VisitAll(visit)
	}
}

func TestExitCodesDocumented(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile(cliDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", cliDocPath, err)
	}
	codes := map[string]int{
		"CodeSuccess": CodeSuccess, "CodeGeneralError": CodeGeneralError,
		"CodeConnectionError": CodeConnectionError, "CodeNoContexts": CodeNoContexts,
		"CodeNoDB": CodeNoDB,
	}
	for name, code := range codes {
		if !strings.Contains(string(doc), "| `"+strconv.Itoa(code)+"` |") {
			t.Errorf("exit code %d (%s) missing from the exit code table in %s", code, name, cliDocPath)
		}
	}
}

func TestBadFlagErrorShape(t *testing.T) {
	t.Parallel()
	// Commands sorts its slice in place, so the walk holds the lock like every Execute.
	cmds := func() []*cobra.Command {
		defer lockRootCmd(t)()
		return contractCommands(rootCmd)
	}()
	for _, c := range cmds {
		path := commandPath(c)
		func() {
			defer lockRootCmd(t)()
			args := append(strings.Fields(path), "--no-such-flag")
			rootCmd.SetArgs(args)
			defer rootCmd.SetArgs(nil)
			err := rootCmd.Execute()
			if err == nil {
				t.Errorf("command %q: no error for an unknown flag", path)
				return
			}
			if p := messageProblem(err.Error()); p != "" {
				t.Errorf("command %q: error %s", path, p)
			}
		}()
	}
}

// TestErrorMessageShape parses every non-test file in this package and checks the literal
// message of each errors.New and fmt.Errorf call, which is what the user sees after "error: ".
func TestErrorMessageShape(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !(pkg.Name == "errors" && sel.Sel.Name == "New" || pkg.Name == "fmt" && sel.Sel.Name == "Errorf") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			msg, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if p := messageProblem(msg); p != "" {
				t.Errorf("%s: error message %s", fset.Position(lit.Pos()), p)
			}
			return true
		})
	}
}
