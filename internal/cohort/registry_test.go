package cohort_test

import (
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestFeaturesAreDeclaredFields checks that every profile feature names a field the report's
// field registry declares, so a renamed scanner field cannot silently become a median.
func TestFeaturesAreDeclaredFields(t *testing.T) {
	t.Parallel()
	for _, f := range cohort.FeatureFields() {
		t.Run(f[0]+"/"+f[1], func(t *testing.T) {
			t.Parallel()
			if !report.DeclaredField(f[0], f[1]) {
				t.Errorf("feature %s/%s has no entry in the report field registry", f[0], f[1])
			}
		})
	}
}
