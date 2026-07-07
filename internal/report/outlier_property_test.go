package report

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"testing"
)

// numericFlat builds the flat per-cluster shape detectNumericOutliers consumes
// from a slice of values, one cluster per value.
func numericFlat(values []float64) ([]string, map[string]map[string]any, map[string]float64) {
	clusters := make([]string, len(values))
	flat := make(map[string]map[string]any, len(values))
	byCluster := make(map[string]float64, len(values))
	for i, v := range values {
		c := fmt.Sprintf("c%02d", i)
		clusters[i] = c
		flat[c] = map[string]any{"v": v}
		byCluster[c] = v
	}
	return clusters, flat, byCluster
}

// TestOutlierUniformFleetHasNoOutliers asserts the core invariant that a fleet
// where every cluster reports the same value produces no outliers: with a MAD
// of zero there is nothing to distinguish.
func TestOutlierUniformFleetHasNoOutliers(t *testing.T) {
	t.Parallel()

	for _, v := range []float64{0, 1, 42, -7.5, 1e6} {
		for _, n := range []int{minMADSample, minMADSample + 5, 30} {
			values := make([]float64, n)
			for i := range values {
				values[i] = v
			}
			clusters, flat, _ := numericFlat(values)
			got := detectNumericOutliers(clusters, flat, "v", "metrics", 3.5)
			if len(got) != 0 {
				t.Errorf("uniform fleet (v=%g, n=%d) produced %d outliers, want 0", v, n, len(got))
			}
		}
	}
}

// TestOutlierMedianClusterNeverFlagged asserts that a cluster whose value equals
// the fleet median is never flagged: its modified z-score is exactly zero. This
// holds for any population, so it is checked against many random fleets.
func TestOutlierMedianClusterNeverFlagged(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		n := 9 + 2*rng.Intn(12) // odd sizes so the median is an actual member
		values := make([]float64, n)
		for i := range values {
			values[i] = rng.NormFloat64()*float64(1+rng.Intn(50)) + float64(rng.Intn(200)-100)
		}
		clusters, flat, byCluster := numericFlat(values)
		med := computeMedian(values)

		for _, o := range detectNumericOutliers(clusters, flat, "v", "metrics", 3.5) {
			if byCluster[o.Cluster] == med {
				t.Fatalf("trial %d: cluster at the median (%g) was flagged as an outlier", trial, med)
			}
		}
	}
}

// TestOutlierThresholdMonotonic asserts that raising the threshold never yields
// more outliers: the flagged set shrinks or holds as the bar rises.
func TestOutlierThresholdMonotonic(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(2))
	thresholds := []float64{1.5, 2.5, 3.5, 5.0, 8.0}
	for trial := 0; trial < 200; trial++ {
		n := minMADSample + rng.Intn(25)
		values := make([]float64, n)
		for i := range values {
			values[i] = rng.NormFloat64() * float64(1+rng.Intn(30))
		}
		clusters, flat, _ := numericFlat(values)

		prev := math.MaxInt32
		for _, th := range thresholds {
			count := len(detectNumericOutliers(clusters, flat, "v", "metrics", th))
			if count > prev {
				t.Fatalf("trial %d: threshold %g gave %d outliers, more than the lower threshold's %d", trial, th, count, prev)
			}
			prev = count
		}
	}
}

// FuzzDetectNumericOutliers feeds arbitrary float populations to the detector and
// asserts it never panics and never emits a non-finite deviation.
func FuzzDetectNumericOutliers(f *testing.F) {
	seed := make([]byte, 8*10)
	for i := 0; i < 10; i++ {
		binary.LittleEndian.PutUint64(seed[i*8:], math.Float64bits(float64(i*i)))
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		var values []float64
		for i := 0; i+8 <= len(data); i += 8 {
			v := math.Float64frombits(binary.LittleEndian.Uint64(data[i : i+8]))
			if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e12 {
				continue
			}
			values = append(values, v)
		}
		if len(values) < minMADSample {
			return
		}
		clusters, flat, _ := numericFlat(values)
		for _, o := range detectNumericOutliers(clusters, flat, "v", "metrics", 3.5) {
			if math.IsNaN(o.Deviation) || math.IsInf(o.Deviation, 0) {
				t.Fatalf("non-finite deviation %v for cluster %s", o.Deviation, o.Cluster)
			}
		}
	})
}
