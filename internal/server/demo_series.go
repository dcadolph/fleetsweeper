package server

import (
	"hash/fnv"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// demoSeriesStep is the synthetic interval between demo scans in the replay
// series, matching the six-hour cadence of the demo trend points.
const demoSeriesStep = 6 * time.Hour

// demoFindingSeries synthesizes a fleet findings timeline of n scans, oldest
// first, from the demo report's findings. Each finding is assigned a
// deterministic birth scan and, for a subset, a short life, so the replay shows
// findings appearing and resolving and the persistence view sees a spread of
// chronic, intermittent, and transient recurrence without any real scan history.
func demoFindingSeries(n int) []scanFindings {
	if n < 2 {
		n = 2
	}
	universe := demoReport().Findings
	now := demoTimestamp()

	series := make([]scanFindings, n)
	for i := 0; i < n; i++ {
		var present []report.Finding
		for _, f := range universe {
			if demoFindingPresent(f, i, n) {
				present = append(present, f)
			}
		}
		series[i] = scanFindings{
			ScanID:    demoScanID + "-t" + itoa(i),
			Timestamp: now.Add(-time.Duration(n-1-i) * demoSeriesStep),
			Findings:  present,
		}
	}
	return series
}

// demoFindingPresent decides whether a finding is present in demo scan index i
// of n, using a deterministic hash of its fingerprint so the pattern is stable
// across restarts. Most findings appear at a birth scan and persist to the
// present; a subset live only a short past window and then resolve.
func demoFindingPresent(f report.Finding, i, n int) bool {
	h := fnv.New32a()
	_, _ = h.Write([]byte(util.Fingerprint(f.Cluster, f.Scanner, f.Title)))
	seed := h.Sum32()

	birth := int(seed % uint32(n))
	if i < birth {
		return false
	}
	// One in four findings is transient: it resolves a few scans after birth
	// instead of persisting to the present.
	if seed%4 == 0 {
		life := 1 + int((seed/4)%3)
		if i >= birth+life {
			return false
		}
	}
	return true
}
