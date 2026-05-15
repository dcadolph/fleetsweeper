package report

import "fmt"

// GenerateTrendFindings produces findings from historical trends.
func GenerateTrendFindings(clusterTrends []ClusterTrend, fleetTrends []FleetTrend) []Finding {
	var findings []Finding

	for _, ct := range clusterTrends {
		if ct.Direction == TrendStable {
			continue
		}
		if len(ct.Points) < 2 {
			continue
		}

		first := ct.Points[0].Value
		last := ct.Points[len(ct.Points)-1].Value
		label := ScannerLabels[ct.Scanner]
		if label == "" {
			label = ct.Scanner
		}

		var sev string
		if ct.Direction == TrendWorsening {
			sev = SeverityWarning
		} else {
			sev = SeverityInfo
		}

		findings = append(findings, Finding{
			Title: fmt.Sprintf("%s: %s %s is %s", ct.Cluster, label, ct.Field, ct.Direction),
			Description: fmt.Sprintf(
				"%s on %s changed from %.1f to %.1f over %d scans.",
				ct.Field, ct.Cluster, first, last, len(ct.Points)),
			Severity: sev,
			Cluster:  ct.Cluster,
			Scanner:  ct.Scanner,
		})
	}

	for _, ft := range fleetTrends {
		if ft.Direction == TrendStable || len(ft.Points) < 2 {
			continue
		}

		first := ft.Points[0].Value
		last := ft.Points[len(ft.Points)-1].Value
		label := ScannerLabels[ft.Scanner]
		if label == "" {
			label = ft.Scanner
		}

		var sev string
		if ft.Direction == TrendWorsening {
			sev = SeverityWarning
		} else {
			sev = SeverityInfo
		}

		findings = append(findings, Finding{
			Title: fmt.Sprintf("Fleet %s drift is %s", label, ft.Direction),
			Description: fmt.Sprintf(
				"Unique values for %s changed from %.0f to %.0f over %d scans.",
				ft.Field, first, last, len(ft.Points)),
			Severity: sev,
			Cluster:  "fleet",
			Scanner:  ft.Scanner,
		})
	}

	return findings
}
