package admission

import (
	"fmt"
	"strings"
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

	checks := DefaultChecks()
	gotNames := make([]string, 0, len(checks))
	for _, c := range checks {
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

// TestNonRootCheckPrecedence verifies the non-root check flags every admitted container whose
// effective user is not explicitly non-root, with container settings winning over pod settings.
func TestNonRootCheckPrecedence(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	root, user := int64(0), int64(1000)
	pod := func(psc *corev1.PodSecurityContext, sc *corev1.SecurityContext) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{
			SecurityContext: psc,
			Containers:      []corev1.Container{{Name: "c", SecurityContext: sc}},
		}}
	}
	tests := []struct {
		Pod           *corev1.Pod
		WantOffenders int
		Fraction      float64
	}{{ // Test 0: Pod runAsNonRoot true with container false offends (R-4).
		Pod: pod(&corev1.PodSecurityContext{RunAsNonRoot: &yes},
			&corev1.SecurityContext{RunAsNonRoot: &no}),
		Fraction: 0.9, WantOffenders: 1,
	}, { // Test 1: Container runAsNonRoot true passes without a pod setting.
		Pod:      pod(nil, &corev1.SecurityContext{RunAsNonRoot: &yes}),
		Fraction: 0.9,
	}, { // Test 2: Pod runAsNonRoot true passes a container that sets nothing.
		Pod:      pod(&corev1.PodSecurityContext{RunAsNonRoot: &yes}, nil),
		Fraction: 0.9,
	}, { // Test 3: Nothing set is unknown and offends.
		Pod:      pod(nil, nil),
		Fraction: 0.9, WantOffenders: 1,
	}, { // Test 4: A runAsUser above zero is explicitly non-root.
		Pod:      pod(nil, &corev1.SecurityContext{RunAsUser: &user}),
		Fraction: 0.9,
	}, { // Test 5: Pod runAsUser 0 under container runAsNonRoot true is root and offends.
		Pod: pod(&corev1.PodSecurityContext{RunAsUser: &root},
			&corev1.SecurityContext{RunAsNonRoot: &yes}),
		Fraction: 0.9, WantOffenders: 1,
	}, { // Test 6: Below threshold stays quiet even with an offender.
		Pod:      pod(nil, nil),
		Fraction: 0.5,
	}, { // Test 7: An ephemeral container is never admitted, so it never offends.
		Pod: &corev1.Pod{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes},
			}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"},
			}},
		}},
		Fraction: 0.9,
	}, { // Test 8: Init and regular offenders are both counted.
		Pod: &corev1.Pod{Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init"}},
			Containers:     []corev1.Container{{Name: "c"}},
		}},
		Fraction: 0.9, WantOffenders: 2,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			warns, deny := nonRootCheck{}.Evaluate(test.Pod, Baseline{NonRootFraction: test.Fraction})
			want := ""
			if test.WantOffenders > 0 {
				want = fmt.Sprintf("%d here do not", test.WantOffenders)
			}
			if !strings.Contains(deny, want) || (want == "") != (deny == "") {
				t.Errorf("deny = %q, want offender phrase %q", deny, want)
			}
			if diff := cmp.Diff(test.WantOffenders > 0, len(warns) > 0); diff != "" {
				t.Errorf("fired mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
