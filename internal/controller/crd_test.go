package controller

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// loadCRD parses a ClusterScan CRD manifest. For the chart copy it drops everything before the
// document separator and every line holding a template action.
func loadCRD(t *testing.T, path string) apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	_, body, _ := strings.Cut(string(raw), "---\n")
	var kept []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "{{") {
			kept = append(kept, line)
		}
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict([]byte(strings.Join(kept, "\n")), &crd); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return crd
}

// TestCRDSchemaCoversStatus verifies every status field the controller writes, every condition
// type, and every condition reason is declared in the CRD. A field missing from a structural
// schema is silently pruned by the API server, so the controller would write it and never see it.
func TestCRDSchemaCoversStatus(t *testing.T) {
	t.Parallel()
	crd := loadCRD(t, "../../deploy/crds/clusterscan.yaml")
	status := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["status"]
	for field := range statusToMap(ClusterScanStatus{}) {
		if _, ok := status.Properties[field]; !ok {
			t.Errorf("status.%s is written by the controller but missing from the CRD schema", field)
		}
	}
	item := status.Properties["conditions"].Items.Schema
	enumOf := func(name string) []string {
		var out []string
		for _, v := range item.Properties[name].Enum {
			out = append(out, strings.Trim(string(v.Raw), `"`))
		}
		return out
	}
	for _, typ := range []string{ConditionReady, ConditionScanning, ConditionFailed} {
		if !slices.Contains(enumOf("type"), typ) {
			t.Errorf("condition type %s missing from the CRD enum", typ)
		}
	}
	for _, reason := range []string{ReasonScanStarted, ReasonScanSucceeded, ReasonScanFailed, ReasonInvalidSpec, ReasonPaused} {
		if !slices.Contains(enumOf("reason"), reason) {
			t.Errorf("condition reason %s missing from the CRD enum", reason)
		}
	}
}

// TestHelmCRDMatchesManifest verifies the chart installs the same ClusterScan schema as
// deploy/crds, so a chart install and a kubectl apply agree.
func TestHelmCRDMatchesManifest(t *testing.T) {
	t.Parallel()
	manifest := loadCRD(t, "../../deploy/crds/clusterscan.yaml")
	chart := loadCRD(t, "../../deploy/helm/fleetsweeper/templates/crd-clusterscan.yaml")
	if diff := cmp.Diff(manifest.Spec, chart.Spec); diff != "" {
		t.Errorf("chart CRD spec drifted from deploy/crds (-manifest +chart):\n%s", diff)
	}
}
