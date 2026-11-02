package kube

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// TestChartKubeconfigSecret renders the Helm chart and verifies kubeconfig.existingSecret mounts
// the Secret read-only and points --kubeconfig at it, and that without it the chart passes no
// kubeconfig and its notes say scans see only the host cluster.
func TestChartKubeconfigSecret(t *testing.T) {
	t.Parallel()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH")
	}
	tests := []struct {
		Set     []string
		WantIn  []string
		WantNot []string
	}{{ // Test 0: A Secret mounts read-only and feeds --kubeconfig.
		Set: []string{"kubeconfig.existingSecret=fleet"},
		WantIn: []string{
			"- --kubeconfig=/var/run/fleetsweeper/kubeconfig",
			"mountPath: /var/run/fleetsweeper\n              readOnly: true",
			"secretName: fleet\n            items:\n              - key: config\n                path: kubeconfig",
			"Scans read every context in the kubeconfig stored in Secret\n   fleet, key config.",
		},
		WantNot: []string{"Scans see only this cluster"},
	}, { // Test 1: A custom key is the one projected.
		Set:    []string{"kubeconfig.existingSecret=fleet", "kubeconfig.key=kubeconfig.yaml"},
		WantIn: []string{"- key: kubeconfig.yaml\n                path: kubeconfig"},
	}, { // Test 2: No Secret, no kubeconfig, and notes say the host cluster only.
		WantIn:  []string{"Scans see only this cluster, through the release's ServiceAccount."},
		WantNot: []string{"--kubeconfig", "/var/run/fleetsweeper"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			args := []string{"install", "fs", "../../deploy/helm/fleetsweeper", "--dry-run=client"}
			for _, s := range test.Set {
				args = append(args, "--set", s)
			}
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm install --dry-run: %v\n%s", err, out)
			}
			got := string(out)
			for _, want := range test.WantIn {
				if !strings.Contains(got, want) {
					t.Errorf("rendered chart missing %q", want)
				}
			}
			for _, not := range test.WantNot {
				if strings.Contains(got, not) {
					t.Errorf("rendered chart holds %q", not)
				}
			}
		})
	}
}
