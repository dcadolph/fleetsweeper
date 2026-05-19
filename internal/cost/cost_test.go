package cost

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// osWriteFileImpl wraps os.WriteFile so test helpers can swap it in tests.
func osWriteFileImpl(name string, data []byte, perm uint32) error {
	return os.WriteFile(name, data, os.FileMode(perm))
}

func TestParseCSV_Basic(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`cluster,period,cost_usd
prod-east,2026-05,2400.50
prod-west,2026-05,1980.00
prod-east,2026-04,2200.00
`)
	m, err := ParseCSV(in)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("want 2 entries, got %d", len(m))
	}
	if m["prod-east"].Period != "2026-05" {
		t.Errorf("expected most-recent period 2026-05 for prod-east; got %s", m["prod-east"].Period)
	}
	if m["prod-east"].USD != 2400.50 {
		t.Errorf("prod-east cost: want 2400.50, got %v", m["prod-east"].USD)
	}
}

func TestParseCSV_HeaderCaseInsensitive(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`Cluster,PERIOD,Cost_USD
a,2026-05,10
`)
	m, err := ParseCSV(in)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if m["a"].USD != 10 {
		t.Errorf("USD: want 10, got %v", m["a"].USD)
	}
}

func TestParseCSV_MissingColumn(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`cluster,cost_usd
a,10
`)
	if _, err := ParseCSV(in); err == nil {
		t.Errorf("expected error when 'period' column is missing")
	}
}

func TestParseCSV_BadCostValue(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`cluster,period,cost_usd
a,2026-05,not-a-number
`)
	if _, err := ParseCSV(in); err == nil {
		t.Errorf("expected error on unparseable cost")
	}
}

func TestLoadCSV_EmptyPath(t *testing.T) {
	t.Parallel()
	m, err := LoadCSV("")
	if err != nil {
		t.Fatalf("LoadCSV(): %v", err)
	}
	if len(m) != 0 {
		t.Errorf("want empty map, got %d", len(m))
	}
}

func TestLoadCSV_File(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cost.csv")
	contents := `cluster,period,cost_usd
prod,2026-05,100.00
`
	if err := writeFile(path, contents); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	m, err := LoadCSV(path)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if m["prod"].USD != 100.00 {
		t.Errorf("want 100.00, got %v", m["prod"].USD)
	}
}

func TestCorrelate_Basic(t *testing.T) {
	t.Parallel()
	r := &report.Report{
		Clusters: []string{"a", "b", "c"},
		ClusterHealths: []report.ClusterHealth{
			{Name: "a", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			{Name: "b", Status: "critical", NodeCount: 5, HealthyNodes: 2},
			{Name: "c", Status: "degraded", NodeCount: 5, HealthyNodes: 5},
		},
	}
	costs := Map{
		"a": {Cluster: "a", Period: "2026-05", USD: 100},
		"b": {Cluster: "b", Period: "2026-05", USD: 1000},
		// "c" intentionally missing
	}
	a := Correlate(r, costs)
	if a.Currency != "USD" {
		t.Errorf("currency: want USD, got %s", a.Currency)
	}
	if a.Period != "2026-05" {
		t.Errorf("period: want 2026-05, got %s", a.Period)
	}
	if a.TotalFleetUSD != 1100 {
		t.Errorf("total fleet: want 1100, got %v", a.TotalFleetUSD)
	}
	// a is perfect (score 100) → drift 0. b is degraded → some drift > 0.
	if a.TotalDriftUSD <= 0 {
		t.Errorf("expected positive total drift, got %v", a.TotalDriftUSD)
	}
	if len(a.MissingCost) != 1 || a.MissingCost[0] != "c" {
		t.Errorf("want missing=[c], got %v", a.MissingCost)
	}
	// b should rank first (highest drift cost).
	if len(a.ByCluster) == 0 || a.ByCluster[0].Cluster != "b" {
		t.Errorf("want b at top of by-cluster, got %+v", a.ByCluster)
	}
}

func TestCorrelate_NilSafe(t *testing.T) {
	t.Parallel()
	a := Correlate(nil, Map{"a": {USD: 100}})
	if a.TotalFleetUSD != 0 || len(a.ByCluster) != 0 {
		t.Errorf("nil report should yield empty analysis, got %+v", a)
	}
}

func TestRoundCents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		In, Want float64
	}{
		{0, 0}, {0.001, 0}, {0.005, 0.01}, {1.234, 1.23}, {1.235, 1.24},
		{-1.235, -1.24}, {99999.999, 100000.00},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := roundCents(c.In); got != c.Want {
				t.Errorf("roundCents(%v): want %v, got %v", c.In, c.Want, got)
			}
		})
	}
}

// writeFile is a tiny stdlib wrapper kept out of the test body for clarity.
func writeFile(path, contents string) error {
	return osWriteFile(path, []byte(contents), 0o644)
}

// osWriteFile is just os.WriteFile, indirected so the test file doesn't have
// to import "os" alongside the helper.
var osWriteFile = func(name string, data []byte, perm uint32) error {
	return osWriteFileImpl(name, data, perm)
}
