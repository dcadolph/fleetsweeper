package util

import (
	"regexp"
	"strings"
)

const (
	// maxNameLen is the Kubernetes object name length limit.
	maxNameLen = 253
	// unnamed is the fallback produced when a name sanitizes to nothing.
	unnamed = "unnamed"
)

var (
	// nameSanitize matches runs of characters outside the DNS-1123 set.
	nameSanitize = regexp.MustCompile(`[^a-z0-9.-]+`)
	// collapseDashes matches runs of two or more dashes.
	collapseDashes = regexp.MustCompile(`-{2,}`)
)

// Truncate shortens s to at most n runes, appending an ellipsis when cut.
func Truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// Plural returns "s" when n is not 1 and the empty string otherwise.
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// SanitizeName returns a DNS-1123-safe rendering of name suitable for use as a
// Kubernetes metadata.name value. It lowercases, replaces runs of invalid
// characters with a dash, collapses adjacent dashes, caps the result at 253
// characters, and trims dashes and dots from both ends so the name starts and
// ends alphanumeric. Pass any fixed prefix as part of name so the cap covers it.
func SanitizeName(name string) string {
	cleaned := nameSanitize.ReplaceAllString(strings.ToLower(name), "-")
	cleaned = collapseDashes.ReplaceAllString(cleaned, "-")
	cleaned = strings.Trim(cleaned, "-.")
	if len(cleaned) > maxNameLen {
		cleaned = strings.TrimRight(cleaned[:maxNameLen], "-.")
	}
	if cleaned == "" {
		return unnamed
	}
	return cleaned
}

// SeverityRank assigns a numeric weight to a severity string for comparison.
// Unknown values rank 0.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// SeverityAtLeast reports whether got meets the want threshold. An empty want
// always passes.
func SeverityAtLeast(got, want string) bool {
	return SeverityRank(got) >= SeverityRank(want)
}
