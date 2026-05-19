package cost

import (
	"strings"
	"testing"
)

// FuzzParseCSV asserts that ParseCSV never panics on arbitrary input.
// It does not check correctness — that is covered by the table-driven
// tests in cost_test.go. The goal here is crash-safety on malformed CSV
// (mismatched columns, exotic quoting, unicode, NULs, huge floats).
func FuzzParseCSV(f *testing.F) {
	seeds := []string{
		"",
		"cluster,period,cost_usd\n",
		"cluster,period,cost_usd\nalpha,2026-01,100.5\nbeta,2026-02,200\n",
		"cluster,period,cost_usd\n,2026-01,0\n",
		"cluster,period,cost_usd\nalpha,2026-01,not-a-number\n",
		"cluster,period,cost_usd\n\"alpha\",\"2026-01\",\"123.45\"\n",
		"cluster,period,cost_usd\nalpha,,0\n",
		"cluster,period,cost_usd\nalpha,2026-01,1e300\n",
		"\xff\xfe\xfd",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseCSV(strings.NewReader(in))
	})
}
