package cohort

// FeatureFields returns the scanner and field each profile feature reads, for tests outside
// the package.
func FeatureFields() [][2]string {
	specs := featureSpecs()
	out := make([][2]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, [2]string{s.scanner, s.field})
	}
	return out
}
