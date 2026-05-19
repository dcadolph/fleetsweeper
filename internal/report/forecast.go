package report

import (
	"math"
	"time"
)

// minForecastPoints is the lowest number of historical observations we will
// fit a forecast against. Below this the regression is dominated by noise.
const minForecastPoints = 4

// FleetScoreHistoryPoint is one observation in a Fleet Score time series.
type FleetScoreHistoryPoint struct {
	// ScanID is the scan that produced the score.
	ScanID string `json:"scan_id"`
	// Timestamp is when the scan executed.
	Timestamp time.Time `json:"timestamp"`
	// Score is the Fleet Score for that scan.
	Score int `json:"score"`
}

// FleetScoreForecast is the predicted next Fleet Score with an uncertainty
// band derived from the regression's standard error. When the input is too
// sparse or too noisy to be meaningful, Sufficient is false and callers
// should hide the forecast in the UI.
type FleetScoreForecast struct {
	// Predicted is the projected Fleet Score at PredictedFor.
	Predicted int `json:"predicted"`
	// Lower is the lower bound of a 95% prediction interval, clamped to 0-100.
	Lower int `json:"lower"`
	// Upper is the upper bound of the 95% prediction interval, clamped to 0-100.
	Upper int `json:"upper"`
	// PredictedFor is the wall-clock time the forecast targets. The handler
	// chooses this (typically "now + median inter-scan gap"); the math is
	// time-aware so a quoted ETA reflects the actual extrapolation.
	PredictedFor time.Time `json:"predicted_for"`
	// Slope is the slope of the fitted line in points per hour. Negative means
	// the fleet is degrading.
	Slope float64 `json:"slope_per_hour"`
	// RSquared is the coefficient of determination for the fit.
	RSquared float64 `json:"r_squared"`
	// Basis is the number of historical points used in the fit.
	Basis int `json:"basis"`
	// Sufficient is true when the fit cleared the minimum sample and noise
	// thresholds and the forecast is worth showing.
	Sufficient bool `json:"sufficient"`
	// Headline is a one-line plain-English summary suitable for the dashboard.
	Headline string `json:"headline"`
}

// ForecastFleetScore fits an OLS line to the given history (oldest first or
// any order; the function sorts by timestamp) and returns a forecast for
// `predictedFor`. If predictedFor is the zero time the function picks a
// sensible target one median scan interval into the future.
func ForecastFleetScore(history []FleetScoreHistoryPoint, predictedFor time.Time) FleetScoreForecast {
	n := len(history)
	if n < minForecastPoints {
		return FleetScoreForecast{
			Basis:      n,
			Sufficient: false,
			Headline:   "Not enough history yet for a forecast.",
		}
	}

	pts := append([]FleetScoreHistoryPoint(nil), history...)
	sortByTimestamp(pts)

	if predictedFor.IsZero() {
		predictedFor = pts[len(pts)-1].Timestamp.Add(medianGap(pts))
	}

	xs := make([]float64, n)
	ys := make([]float64, n)
	t0 := pts[0].Timestamp
	for i, p := range pts {
		xs[i] = p.Timestamp.Sub(t0).Hours()
		ys[i] = float64(p.Score)
	}

	slope, intercept, rSq, stdErr := ols(xs, ys)
	xPredict := predictedFor.Sub(t0).Hours()
	predicted := slope*xPredict + intercept
	predicted = math.Max(0, math.Min(100, predicted))

	// 95% interval uses 1.96 * stderr on a normal approximation. For very
	// small n the t-distribution would be wider; we keep the normal estimate
	// since the user-facing band is for intuition, not a clinical claim.
	margin := 1.96 * stdErr
	if math.IsNaN(margin) || math.IsInf(margin, 0) {
		margin = 0
	}

	forecast := FleetScoreForecast{
		Predicted:    int(math.Round(predicted)),
		Lower:        int(math.Round(math.Max(0, predicted-margin))),
		Upper:        int(math.Round(math.Min(100, predicted+margin))),
		PredictedFor: predictedFor,
		Slope:        slope,
		RSquared:     rSq,
		Basis:        n,
		Sufficient:   rSq >= 0.25 || math.Abs(slope) > 0.1,
	}
	forecast.Headline = forecastHeadline(forecast, pts[len(pts)-1].Score)
	return forecast
}

// ols computes ordinary least squares slope, intercept, R-squared, and the
// regression standard error (sqrt of mean squared residual). Returns zeros
// for degenerate inputs (constant x or n < 2) so callers can detect and
// suppress meaningless results via R² or the Sufficient flag.
func ols(xs, ys []float64) (slope, intercept, rSquared, stdErr float64) {
	n := float64(len(xs))
	if n < 2 {
		return 0, 0, 0, 0
	}
	var sumX, sumY, sumXY, sumXX, sumYY float64
	for i := range xs {
		sumX += xs[i]
		sumY += ys[i]
		sumXY += xs[i] * ys[i]
		sumXX += xs[i] * xs[i]
		sumYY += ys[i] * ys[i]
	}
	meanX := sumX / n
	meanY := sumY / n
	denom := sumXX - meanX*sumX
	if denom == 0 {
		return 0, meanY, 0, 0
	}
	slope = (sumXY - meanX*sumY) / denom
	intercept = meanY - slope*meanX

	var ssRes, ssTot float64
	for i := range xs {
		predicted := slope*xs[i] + intercept
		residual := ys[i] - predicted
		ssRes += residual * residual
		ssTot += (ys[i] - meanY) * (ys[i] - meanY)
	}
	if ssTot > 0 {
		rSquared = 1 - ssRes/ssTot
	}
	if n > 2 {
		stdErr = math.Sqrt(ssRes / (n - 2))
	}
	return slope, intercept, rSquared, stdErr
}

// sortByTimestamp orders the slice in place, oldest first.
func sortByTimestamp(pts []FleetScoreHistoryPoint) {
	for i := 1; i < len(pts); i++ {
		for j := i; j > 0 && pts[j-1].Timestamp.After(pts[j].Timestamp); j-- {
			pts[j-1], pts[j] = pts[j], pts[j-1]
		}
	}
}

// medianGap returns the median gap between consecutive scans. Used as the
// default forecast horizon so the projection is "the next scan, whenever
// that lands" rather than an arbitrary minute count.
func medianGap(pts []FleetScoreHistoryPoint) time.Duration {
	if len(pts) < 2 {
		return time.Hour
	}
	gaps := make([]time.Duration, 0, len(pts)-1)
	for i := 1; i < len(pts); i++ {
		gaps = append(gaps, pts[i].Timestamp.Sub(pts[i-1].Timestamp))
	}
	for i := 1; i < len(gaps); i++ {
		for j := i; j > 0 && gaps[j-1] > gaps[j]; j-- {
			gaps[j-1], gaps[j] = gaps[j], gaps[j-1]
		}
	}
	mid := gaps[len(gaps)/2]
	if mid <= 0 {
		return time.Hour
	}
	return mid
}

// forecastHeadline composes a one-line plain-English summary based on the
// direction and magnitude of the predicted change.
func forecastHeadline(f FleetScoreForecast, currentScore int) string {
	if !f.Sufficient {
		return "Trend too flat or noisy to forecast confidently."
	}
	delta := f.Predicted - currentScore
	switch {
	case delta >= 5:
		return "Projected to improve sharply."
	case delta >= 2:
		return "Projected to improve."
	case delta <= -5:
		return "Projected to degrade sharply."
	case delta <= -2:
		return "Projected to degrade."
	default:
		return "Projected to hold steady."
	}
}
