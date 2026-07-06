# Fleet Score

The Fleet Score is a single 0-100 number that summarizes fleet health from
the most recent scan. A letter grade (A-F) is rendered alongside for quick
recognition.

## How it is computed

The score is a weighted blend of:

1. **Average cluster health.** Each cluster is rated by counting critical
   and warning findings against a soft cap, producing a per-cluster
   subscore. The fleet score averages those.
2. **Drift severity.** A penalty proportional to the count of unique
   divergences across the fleet.
3. **Version skew.** A penalty when clusters lag the maximum observed
   Kubernetes minor version by more than two releases.
4. **Critical fingerprints.** A small penalty per outstanding critical
   finding fingerprint, capped so a single noisy scanner cannot dominate.

The exact weights live in `internal/report/score.go` and are documented
inline. They are tuned so a fully healthy single-cluster fleet scores 100,
a typical multi-cluster fleet scores in the high 80s to low 90s, and a
fleet with ongoing critical findings drops into the 70s.

## Grade thresholds

| Grade | Range |
| --- | --- |
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

## Trends

A regression line is fitted through the score history. The trend is only
surfaced as "improving" or "regressing" when the t-statistic exceeds 2.0
so a two-scan window does not produce false alarms. The forecast at
`/api/forecast/fleet-score` projects 30 days out using the same fit.
