package admission

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
)

// TestCheckNames verifies each built-in check reports its stable identifier
// and that DefaultChecks returns exactly those checks.
func TestCheckNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Check    Check
		WantName string
	}{
		{Check: digestPinCheck{}, WantName: "digest-pin"},              // Test 0.
		{Check: nonRootCheck{}, WantName: "non-root"},                  // Test 1.
		{Check: noPrivEscCheck{}, WantName: "no-privilege-escalation"}, // Test 2.
		{Check: namedSACheck{}, WantName: "named-service-account"},     // Test 3.
		{Check: readOnlyRootFSCheck{}, WantName: "read-only-root-fs"},  // Test 4.
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			if got := test.Check.Name(); got != test.WantName {
				t.Errorf("test %d: Name() = %q, want %q", testNum, got, test.WantName)
			}
		})
	}

	var gotNames []string
	for _, c := range DefaultChecks() {
		gotNames = append(gotNames, c.Name())
	}
	wantNames := []string{
		"digest-pin", "non-root", "no-privilege-escalation",
		"named-service-account", "read-only-root-fs",
	}
	if diff := cmp.Diff(wantNames, gotNames); diff != "" {
		t.Errorf("DefaultChecks names mismatch (-want +got):\n%s", diff)
	}
}

// TestNoPrivEscCheck verifies the no-privilege-escalation check fires only
// when the baseline is above threshold and a container leaves
// allowPrivilegeEscalation unset or true.
func TestNoPrivEscCheck(t *testing.T) {
	t.Parallel()
	yes := true
	no := false
	sc := func(allow *bool) *corev1.SecurityContext {
		return &corev1.SecurityContext{AllowPrivilegeEscalation: allow}
	}
	tests := []struct {
		Pod      *corev1.Pod
		Fraction float64
		WantFire bool
	}{
		{ // Test 0: Below threshold stays quiet even with an offending container.
			Pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
			Fraction: 0.5, WantFire: false,
		},
		{ // Test 1: nil SecurityContext counts as escalation-allowed.
			Pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
			Fraction: 0.9, WantFire: true,
		},
		{ // Test 2: SecurityContext with nil flag counts as escalation-allowed.
			Pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", SecurityContext: sc(nil)}}}},
			Fraction: 0.9, WantFire: true,
		},
		{ // Test 3: Explicit allowPrivilegeEscalation=true offends.
			Pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", SecurityContext: sc(&yes)}}}},
			Fraction: 0.9, WantFire: true,
		},
		{ // Test 4: allowPrivilegeEscalation=false is clean.
			Pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", SecurityContext: sc(&no)}}}},
			Fraction: 0.9, WantFire: false,
		},
		{ // Test 5: An offending init container fires even when the main one is clean.
			Pod: &corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", SecurityContext: sc(&yes)}},
				Containers:     []corev1.Container{{Name: "c", SecurityContext: sc(&no)}},
			}},
			Fraction: 0.9, WantFire: true,
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			warns, deny := noPrivEscCheck{}.Evaluate(test.Pod, Baseline{NoPrivilegeEscalationFraction: test.Fraction})
			fired := len(warns) > 0
			if fired != test.WantFire {
				t.Errorf("test %d: fired = %v, want %v (warns=%v)", testNum, fired, test.WantFire, warns)
			}
			if fired && deny == "" {
				t.Errorf("test %d: firing check must return a deny reason", testNum)
			}
			if !fired && deny != "" {
				t.Errorf("test %d: quiet check must not return a deny reason, got %q", testNum, deny)
			}
		})
	}
}

// TestNonRootCheckContainerLevel verifies a container-level runAsNonRoot=true
// clears the non-root check even without a pod-level setting.
func TestNonRootCheckContainerLevel(t *testing.T) {
	t.Parallel()
	yes := true
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:            "c",
			SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes},
		}},
	}}
	warns, deny := nonRootCheck{}.Evaluate(pod, Baseline{NonRootFraction: 0.9})
	if len(warns) != 0 || deny != "" {
		t.Errorf("container-level runAsNonRoot should pass, got warns=%v deny=%q", warns, deny)
	}
}
