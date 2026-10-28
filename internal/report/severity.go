package report

import (
	"fmt"
	"strings"
)

// applySeverity assigns severity levels to all divergences in a section based
// on the scanner name and field.
func applySeverity(scannerName string, section *SectionReport) {
	for i := range section.Divergences {
		section.Divergences[i].Severity = classifySeverity(scannerName, section.Divergences[i].Field)
	}
}

// classifySeverity determines the severity for a divergent field.
func classifySeverity(scannerName, field string) string {
	if fields, ok := criticalFields[scannerName]; ok {
		if _, ok := fields[field]; ok {
			return SeverityCritical
		}
	}
	if fields, ok := warningFields[scannerName]; ok {
		if _, ok := fields[field]; ok {
			return SeverityWarning
		}
	}
	return SeverityInfo
}

// VersionSkewSeverity returns the severity for a set of Kubernetes version
// strings present across a fleet. Patch differences are info, single-minor
// skew is warning, and skew of more than one minor (outside Kubernetes' own
// supported skew policy) is critical. Strings that fail to parse are ignored,
// so a single garbled response cannot escalate severity.
func VersionSkewSeverity(versions []string) string {
	if len(versions) < 2 {
		return SeverityInfo
	}
	minMinor, maxMinor := -1, -1
	patchSet := make(map[[3]int]bool)
	for _, v := range versions {
		major, minor, patch, ok := parseSemver(v)
		if !ok {
			continue
		}
		patchSet[[3]int{major, minor, patch}] = true
		if minMinor == -1 || minor < minMinor {
			minMinor = minor
		}
		if maxMinor == -1 || minor > maxMinor {
			maxMinor = minor
		}
	}
	if len(patchSet) <= 1 {
		return SeverityInfo
	}
	if maxMinor-minMinor >= 2 {
		return SeverityCritical
	}
	if maxMinor != minMinor {
		return SeverityWarning
	}
	return SeverityInfo
}

// parseSemver extracts the major.minor.patch components from a Kubernetes
// version string such as "v1.31.2" or "1.31.2-gke.500". Returns ok=false when
// the string does not start with a recognizable version triple.
func parseSemver(v string) (major, minor, patch int, ok bool) {
	s := strings.TrimPrefix(v, "v")
	core := s
	for i, r := range s {
		if r == '-' || r == '+' {
			core = s[:i]
			break
		}
	}
	if _, err := fmt.Sscanf(core, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}
