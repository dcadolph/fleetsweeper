package admission

import (
	"os/exec"
	"strings"
	"testing"
)

// TestChartDefaultNamespaceSelector verifies the chart's default webhook namespaceSelector
// excludes kube-system and namespaces labeled fleetsweeper.dev/admission=ignore.
func TestChartDefaultNamespaceSelector(t *testing.T) {
	t.Parallel()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH")
	}
	out, err := exec.Command(helm, "template", "fs", "../../deploy/helm/fleetsweeper",
		"--set", "admission.enabled=true").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		"namespaceSelector:",
		"key: kubernetes.io/metadata.name",
		"- kube-system",
		"key: fleetsweeper.dev/admission",
		"- ignore",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered chart missing %q", want)
		}
	}
}
