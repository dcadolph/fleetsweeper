package report

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var testTrendStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// testTrendPoints builds one point per hour from the given values.
func testTrendPoints(values ...float64) []TrendPoint {
	points := make([]TrendPoint, 0, len(values))
	for i, v := range values {
		points = append(points, TrendPoint{
			Timestamp: testTrendStart.Add(time.Duration(i) * time.Hour),
			ScanID:    fmt.Sprintf("s%d", i),
			Value:     v,
		})
	}
	return points
}

// testTrendScans builds n scan metas, one per hour.
func testTrendScans(n int) []ScanMeta {
	scans := make([]ScanMeta, 0, n)
	for i := range n {
		scans = append(scans, ScanMeta{
			ID:        fmt.Sprintf("s%d", i),
			Timestamp: testTrendStart.Add(time.Duration(i) * time.Hour),
		})
	}
	return scans
}

// TestFitDirection verifies direction and confidence classification.
func TestFitDirection(t *testing.T) {
	t.Parallel()

	sameTime := testTrendPoints(1, 2, 3, 4, 5)
	for i := range sameTime {
		sameTime[i].Timestamp = testTrendStart
	}

	tests := []struct {
		Name           string
		Points         []TrendPoint
		UpIsBad        bool
		WantDirection  TrendDirection
		WantConfidence string
	}{
		{ // Test 0: Fewer than the minimum sample is stable and low.
			Name:           "too few points",
			Points:         testTrendPoints(1, 2, 3, 4),
			UpIsBad:        true,
			WantDirection:  TrendStable,
			WantConfidence: "low",
		},
		{ // Test 1: Identical timestamps are stable and low.
			Name:           "identical timestamps",
			Points:         sameTime,
			UpIsBad:        true,
			WantDirection:  TrendStable,
			WantConfidence: "low",
		},
		{ // Test 2: A flat series is stable and high.
			Name:           "flat series",
			Points:         testTrendPoints(0, 0, 0, 0, 0, 0),
			UpIsBad:        true,
			WantDirection:  TrendStable,
			WantConfidence: "high",
		},
		{ // Test 3: A rising series is worsening when up is bad.
			Name:           "rising up is bad",
			Points:         testTrendPoints(10, 12, 13, 15, 16, 18),
			UpIsBad:        true,
			WantDirection:  TrendWorsening,
			WantConfidence: "high",
		},
		{ // Test 4: A rising series is improving when up is good.
			Name:           "rising up is good",
			Points:         testTrendPoints(10, 12, 13, 15, 16, 18),
			UpIsBad:        false,
			WantDirection:  TrendImproving,
			WantConfidence: "high",
		},
		{ // Test 5: A falling series is improving when up is bad.
			Name:           "falling up is bad",
			Points:         testTrendPoints(18, 16, 15, 13, 12, 10),
			UpIsBad:        true,
			WantDirection:  TrendImproving,
			WantConfidence: "high",
		},
		{ // Test 6: A noisy series under the R-squared floor is stable and low.
			Name:           "noisy series",
			Points:         testTrendPoints(10, 50, 10, 50, 10, 50),
			UpIsBad:        true,
			WantDirection:  TrendStable,
			WantConfidence: "low",
		},
		{ // Test 7: A perfectly linear rise is worsening and high.
			Name:           "perfect fit rising",
			Points:         testTrendPoints(1, 2, 3, 4, 5, 6),
			UpIsBad:        true,
			WantDirection:  TrendWorsening,
			WantConfidence: "high",
		},
		{ // Test 8: A perfectly linear fall is improving and high.
			Name:           "perfect fit falling",
			Points:         testTrendPoints(6, 5, 4, 3, 2, 1),
			UpIsBad:        true,
			WantDirection:  TrendImproving,
			WantConfidence: "high",
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := fitDirection(test.Points, test.UpIsBad)
			if got.Direction != test.WantDirection {
				t.Errorf("direction = %q, want %q", got.Direction, test.WantDirection)
			}
			if got.Confidence != test.WantConfidence {
				t.Errorf("confidence = %q, want %q", got.Confidence, test.WantConfidence)
			}
		})
	}
}

// TestComputeClusterTrends verifies cluster trend assembly.
func TestComputeClusterTrends(t *testing.T) {
	t.Parallel()

	scans := testTrendScans(6)
	rising := []float64{10, 12, 13, 15, 16, 18}
	results := make(map[string]map[string]map[string]any)
	for i, scan := range scans {
		results[scan.ID] = map[string]map[string]any{
			"node-health": {"unhealthy_nodes": rising[i]},
		}
	}
	shuffled := []ScanMeta{scans[3], scans[0], scans[5], scans[2], scans[4], scans[1]}

	missing := make(map[string]map[string]map[string]any)
	for i, scan := range scans {
		if i%2 == 0 {
			missing[scan.ID] = map[string]map[string]any{
				"node-health": {"unhealthy_nodes": rising[i]},
			}
		} else {
			missing[scan.ID] = map[string]map[string]any{"events": {"warning_events": 1.0}}
		}
	}

	tests := []struct {
		Name          string
		Scans         []ScanMeta
		Results       map[string]map[string]map[string]any
		WantDirection TrendDirection
		WantCount     int
		WantIDs       []string
	}{
		{ // Test 0: A rising unhealthy_nodes series is worsening.
			Name:          "rising",
			Scans:         scans,
			Results:       results,
			WantDirection: TrendWorsening,
			WantCount:     1,
			WantIDs:       []string{"s0", "s1", "s2", "s3", "s4", "s5"},
		},
		{ // Test 1: Scans missing the scanner are skipped, leaving too few points.
			Name:      "missing scanner",
			Scans:     scans,
			Results:   missing,
			WantCount: 0,
		},
		{ // Test 2: Points are sorted by time when scans are shuffled.
			Name:          "shuffled",
			Scans:         shuffled,
			Results:       results,
			WantDirection: TrendWorsening,
			WantCount:     1,
			WantIDs:       []string{"s0", "s1", "s2", "s3", "s4", "s5"},
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := ComputeClusterTrends("c1", test.Scans, test.Results)
			if len(got) != test.WantCount {
				t.Fatalf("trend count = %d, want %d", len(got), test.WantCount)
			}
			if test.WantCount == 0 {
				return
			}
			trend := got[0]
			if trend.Cluster != "c1" || trend.Scanner != "node-health" ||
				trend.Field != "unhealthy_nodes" {
				t.Errorf("trend identity = %s/%s/%s", trend.Cluster, trend.Scanner, trend.Field)
			}
			if trend.Direction != test.WantDirection {
				t.Errorf("direction = %q, want %q", trend.Direction, test.WantDirection)
			}
			ids := make([]string, 0, len(trend.Points))
			for _, p := range trend.Points {
				ids = append(ids, p.ScanID)
			}
			if diff := cmp.Diff(test.WantIDs, ids, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("point order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestComputeFleetTrends verifies fleet uniqueness trends.
func TestComputeFleetTrends(t *testing.T) {
	t.Parallel()

	scans := testTrendScans(6)
	growing := make(map[string]map[string]map[string]any)
	for i, scan := range scans {
		unique := 1 + i/3*2
		clusters := make(map[string]map[string]any)
		for c := range 3 {
			version := fmt.Sprintf("v1.%d", c%unique)
			clusters[fmt.Sprintf("c%d", c)] = map[string]any{
				"version": map[string]any{"git_version": version},
			}
		}
		growing[scan.ID] = clusters
	}
	// The first three scans hold 1 unique version and the last three hold 3.
	single := map[string]map[string]map[string]any{
		"s0": {"c0": {"version": map[string]any{"git_version": "v1.0"}}},
	}

	tests := []struct {
		Name          string
		Scans         []ScanMeta
		Results       map[string]map[string]map[string]any
		WantCount     int
		WantDirection TrendDirection
		WantFirst     float64
		WantLast      float64
	}{
		{ // Test 0: Versions going from 1 to 3 unique values are worsening.
			Name:          "diverging",
			Scans:         scans,
			Results:       growing,
			WantCount:     1,
			WantDirection: TrendWorsening,
			WantFirst:     1,
			WantLast:      3,
		},
		{ // Test 1: Fewer than 2 points gives no trend.
			Name:      "single point",
			Scans:     scans,
			Results:   single,
			WantCount: 0,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := ComputeFleetTrends(test.Scans, test.Results)
			if len(got) != test.WantCount {
				t.Fatalf("trend count = %d, want %d", len(got), test.WantCount)
			}
			if test.WantCount == 0 {
				return
			}
			trend := got[0]
			if trend.Direction != test.WantDirection {
				t.Errorf("direction = %q, want %q", trend.Direction, test.WantDirection)
			}
			if trend.Points[0].Value != test.WantFirst ||
				trend.Points[len(trend.Points)-1].Value != test.WantLast {
				t.Errorf("points = %v", trend.Points)
			}
		})
	}
}

// TestGenerateTrendFindings verifies finding generation from trends.
func TestGenerateTrendFindings(t *testing.T) {
	t.Parallel()

	points := testTrendPoints(10, 12, 13, 15, 16, 18)

	tests := []struct {
		Name        string
		Cluster     []ClusterTrend
		Fleet       []FleetTrend
		WantCount   int
		WantCluster string
		WantScanner string
	}{
		{ // Test 0: A stable trend gives no findings.
			Name: "stable",
			Cluster: []ClusterTrend{{
				Cluster: "c1", Scanner: "node-health", Field: "unhealthy_nodes",
				Points: points, Direction: TrendStable,
			}},
			Fleet: []FleetTrend{{
				Scanner: "version", Field: "git_version", Points: points,
				Direction: TrendStable,
			}},
			WantCount: 0,
		},
		{ // Test 1: A fleet trend uses the fleet cluster and its scanner.
			Name: "fleet",
			Fleet: []FleetTrend{{
				Scanner: "version", Field: "git_version", Points: points,
				Direction: TrendWorsening,
			}},
			WantCount:   1,
			WantCluster: "fleet",
			WantScanner: "version",
		},
		{ // Test 2: A worsening cluster trend carries its cluster and scanner.
			Name: "cluster",
			Cluster: []ClusterTrend{{
				Cluster: "c1", Scanner: "node-health", Field: "unhealthy_nodes",
				Points: points, Direction: TrendWorsening,
			}},
			WantCount:   1,
			WantCluster: "c1",
			WantScanner: "node-health",
		},
		{ // Test 3: A trend with fewer than 2 points is skipped.
			Name: "short",
			Cluster: []ClusterTrend{{
				Cluster: "c1", Scanner: "node-health", Field: "unhealthy_nodes",
				Points: points[:1], Direction: TrendWorsening,
			}},
			WantCount: 0,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := GenerateTrendFindings(test.Cluster, test.Fleet)
			if len(got) != test.WantCount {
				t.Fatalf("finding count = %d, want %d", len(got), test.WantCount)
			}
			if test.WantCount == 0 {
				return
			}
			if got[0].Cluster != test.WantCluster || got[0].Scanner != test.WantScanner {
				t.Errorf("finding = %s/%s", got[0].Cluster, got[0].Scanner)
			}
			if got[0].Severity != SeverityWarning {
				t.Errorf("severity = %q, want %q", got[0].Severity, SeverityWarning)
			}
		})
	}
}
