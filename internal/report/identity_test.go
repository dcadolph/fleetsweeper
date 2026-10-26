package report

import (
	"fmt"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestIdentityScannersNotNorms verifies the geo scanner's per-cluster
// location is neither a divergence nor a norm.
func TestIdentityScannersNotNorms(t *testing.T) {
	t.Parallel()
	clusters := make([]string, 10)
	results := map[string]map[string]scanner.Result{}
	for i := range clusters {
		clusters[i] = fmt.Sprintf("c%02d", i)
		lat := 10.0 * float64(i)
		if i == 9 {
			lat = 89
		}
		results[clusters[i]] = map[string]scanner.Result{"geo": {Scanner: "geo", Data: map[string]any{"lat": lat, "lng": -lat, "has_location": i%2 == 0, "site": clusters[i]}}}
	}
	r := Build(clusters, results, BuildOptions{})
	if sec := r.Sections["geo"]; sec == nil || !sec.Uniform || len(sec.Divergences) != 0 {
		t.Errorf("geo section: want uniform with no divergences, got %+v", sec)
	}
	for _, o := range r.Outliers {
		if o.Scanner == "geo" {
			t.Errorf("geo outlier on %s/%s", o.Cluster, o.Field)
		}
	}
}
