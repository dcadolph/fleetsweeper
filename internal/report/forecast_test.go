package report

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestForecastFleetScore_InsufficientHistory(t *testing.T) {
	t.Parallel()
	now := time.Now()
	in := []FleetScoreHistoryPoint{
		{Timestamp: now.Add(-2 * time.Hour), Score: 80},
		{Timestamp: now.Add(-1 * time.Hour), Score: 75},
		{Timestamp: now, Score: 70},
	}
	got := ForecastFleetScore(in, time.Time{})
	if got.Sufficient {
		t.Errorf("want sufficient=false with %d points, got true", len(in))
	}
	if got.Basis != 3 {
		t.Errorf("basis: want 3, got %d", got.Basis)
	}
}

func TestForecastFleetScore_DegradingTrend(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// Linear degradation: 90, 85, 80, 75, 70 over 4 hours.
	in := []FleetScoreHistoryPoint{
		{Timestamp: now.Add(-4 * time.Hour), Score: 90},
		{Timestamp: now.Add(-3 * time.Hour), Score: 85},
		{Timestamp: now.Add(-2 * time.Hour), Score: 80},
		{Timestamp: now.Add(-1 * time.Hour), Score: 75},
		{Timestamp: now, Score: 70},
	}
	got := ForecastFleetScore(in, now.Add(time.Hour))
	if !got.Sufficient {
		t.Errorf("expected sufficient=true on clean linear data; got %+v", got)
	}
	if got.Predicted >= 70 {
		t.Errorf("expected predicted < 70 for degrading trend; got %d", got.Predicted)
	}
	if got.Slope >= 0 {
		t.Errorf("expected negative slope; got %f", got.Slope)
	}
	if got.RSquared < 0.95 {
		t.Errorf("expected near-perfect R²; got %f", got.RSquared)
	}
}

func TestForecastFleetScore_ClampsToBounds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// Steep degradation: would extrapolate below zero.
	in := []FleetScoreHistoryPoint{
		{Timestamp: now.Add(-4 * time.Hour), Score: 40},
		{Timestamp: now.Add(-3 * time.Hour), Score: 30},
		{Timestamp: now.Add(-2 * time.Hour), Score: 20},
		{Timestamp: now.Add(-1 * time.Hour), Score: 10},
		{Timestamp: now, Score: 5},
	}
	got := ForecastFleetScore(in, now.Add(5*time.Hour))
	if got.Predicted < 0 || got.Predicted > 100 {
		t.Errorf("predicted out of [0,100]: %d", got.Predicted)
	}
	if got.Lower < 0 || got.Upper > 100 {
		t.Errorf("interval out of [0,100]: [%d,%d]", got.Lower, got.Upper)
	}
}

func TestOLS_ConstantSeries(t *testing.T) {
	t.Parallel()
	// Constant ys → slope 0, intercept = mean.
	slope, intercept, r2, se := ols([]float64{0, 1, 2, 3}, []float64{50, 50, 50, 50})
	if math.Abs(slope) > 1e-9 {
		t.Errorf("slope: want 0, got %f", slope)
	}
	if math.Abs(intercept-50) > 1e-9 {
		t.Errorf("intercept: want 50, got %f", intercept)
	}
	if math.Abs(r2) > 1e-9 {
		t.Errorf("r²: want 0 (no variance), got %f", r2)
	}
	if se > 1e-9 {
		t.Errorf("stderr: want 0, got %f", se)
	}
}

func TestOLS_PerfectFit(t *testing.T) {
	t.Parallel()
	slope, intercept, r2, _ := ols([]float64{0, 1, 2, 3, 4}, []float64{10, 12, 14, 16, 18})
	if math.Abs(slope-2) > 1e-9 {
		t.Errorf("slope: want 2, got %f", slope)
	}
	if math.Abs(intercept-10) > 1e-9 {
		t.Errorf("intercept: want 10, got %f", intercept)
	}
	if math.Abs(r2-1) > 1e-9 {
		t.Errorf("r²: want 1, got %f", r2)
	}
}

func TestMedianGap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		Name string
		In   []time.Duration
		Want time.Duration
	}{
		{"uniform", []time.Duration{time.Hour, time.Hour, time.Hour}, time.Hour},
		{"odd", []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}, 2 * time.Hour},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d: %s", i, c.Name), func(t *testing.T) {
			t.Parallel()
			base := time.Now()
			pts := []FleetScoreHistoryPoint{{Timestamp: base, Score: 50}}
			cursor := base
			for _, gap := range c.In {
				cursor = cursor.Add(gap)
				pts = append(pts, FleetScoreHistoryPoint{Timestamp: cursor, Score: 50})
			}
			if got := medianGap(pts); got.Round(time.Second) != c.Want.Round(time.Second) {
				t.Errorf("medianGap: want %s, got %s", c.Want, got)
			}
		})
	}
}

func TestForecastFleetScore_Headlines(t *testing.T) {
	t.Parallel()
	now := time.Now()
	mkPts := func(scores ...int) []FleetScoreHistoryPoint {
		out := make([]FleetScoreHistoryPoint, len(scores))
		for i, s := range scores {
			out[i] = FleetScoreHistoryPoint{Timestamp: now.Add(time.Duration(i) * time.Hour), Score: s}
		}
		return out
	}
	got := ForecastFleetScore(mkPts(50, 55, 60, 65, 70), now.Add(5*time.Hour))
	if got.Headline == "" {
		t.Errorf("expected non-empty headline")
	}
}
