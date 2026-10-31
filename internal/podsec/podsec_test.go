package podsec

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
)

// testBool decodes a matrix code into a runAsNonRoot pointer: "-" is unset, "t" true, "f" false.
func testBool(t *testing.T, code string) *bool {
	t.Helper()
	switch code {
	case "-":
		return nil
	case "t":
		v := true
		return &v
	case "f":
		v := false
		return &v
	}
	t.Fatalf("unknown bool code %q", code)
	return nil
}

// testUser decodes a matrix code into a runAsUser pointer: "-" is unset, anything else a UID.
func testUser(t *testing.T, code string) *int64 {
	t.Helper()
	if code == "-" {
		return nil
	}
	v, err := strconv.ParseInt(code, 10, 64)
	if err != nil {
		t.Fatalf("bad user code %q: %v", code, err)
	}
	return &v
}

// testPod builds a pod whose security context carries the coded runAsNonRoot and runAsUser.
// It leaves the security context nil when both codes are unset.
func testPod(t *testing.T, nonRoot, user string) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	if nonRoot == "-" && user == "-" {
		return pod
	}
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: testBool(t, nonRoot),
		RunAsUser:    testUser(t, user),
	}
	return pod
}

// testContainer builds a container whose security context carries the coded runAsNonRoot and
// runAsUser. It leaves the security context nil when both codes are unset.
func testContainer(t *testing.T, nonRoot, user string) corev1.Container {
	t.Helper()
	c := corev1.Container{Name: "app"}
	if nonRoot == "-" && user == "-" {
		return c
	}
	c.SecurityContext = &corev1.SecurityContext{
		RunAsNonRoot: testBool(t, nonRoot),
		RunAsUser:    testUser(t, user),
	}
	return c
}

// testSeccompPod builds a pod with the given pod-level seccomp profile type, or none when empty.
func testSeccompPod(typ corev1.SeccompProfileType) *corev1.Pod {
	pod := &corev1.Pod{}
	if typ != "" {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: typ},
		}
	}
	return pod
}

// testSeccompContainer builds a container with the given seccomp profile type, or none when empty.
func testSeccompContainer(typ corev1.SeccompProfileType) corev1.Container {
	c := corev1.Container{Name: "app"}
	if typ != "" {
		c.SecurityContext = &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: typ},
		}
	}
	return c
}

// testPtr returns a pointer to v.
func testPtr[T any](v T) *T {
	return &v
}

func TestRunAsNonRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		PodNonRoot string
		NonRoot    string
		WantValue  bool
		WantSet    bool
	}{
		// Test 0: Nothing set.
		{PodNonRoot: "-", NonRoot: "-", WantValue: false, WantSet: false},
		// Test 1: Container true only.
		{PodNonRoot: "-", NonRoot: "t", WantValue: true, WantSet: true},
		// Test 2: Container false only.
		{PodNonRoot: "-", NonRoot: "f", WantValue: false, WantSet: true},
		// Test 3: Pod true only.
		{PodNonRoot: "t", NonRoot: "-", WantValue: true, WantSet: true},
		// Test 4: Pod true, container true.
		{PodNonRoot: "t", NonRoot: "t", WantValue: true, WantSet: true},
		// Test 5: Pod true, container false, container wins.
		{PodNonRoot: "t", NonRoot: "f", WantValue: false, WantSet: true},
		// Test 6: Pod false only.
		{PodNonRoot: "f", NonRoot: "-", WantValue: false, WantSet: true},
		// Test 7: Pod false, container true, container wins.
		{PodNonRoot: "f", NonRoot: "t", WantValue: true, WantSet: true},
		// Test 8: Pod false, container false.
		{PodNonRoot: "f", NonRoot: "f", WantValue: false, WantSet: true},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			pod := testPod(t, test.PodNonRoot, "-")
			gotValue, gotSet := RunAsNonRoot(pod, testContainer(t, test.NonRoot, "-"))
			if diff := cmp.Diff(test.WantValue, gotValue); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantSet, gotSet); diff != "" {
				t.Errorf("set mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunAsUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		PodUser   string
		User      string
		WantValue int64
		WantSet   bool
	}{
		// Test 0: Nothing set.
		{PodUser: "-", User: "-", WantValue: 0, WantSet: false},
		// Test 1: Container 0 only.
		{PodUser: "-", User: "0", WantValue: 0, WantSet: true},
		// Test 2: Container 1000 only.
		{PodUser: "-", User: "1000", WantValue: 1000, WantSet: true},
		// Test 3: Pod 0 only.
		{PodUser: "0", User: "-", WantValue: 0, WantSet: true},
		// Test 4: Pod 0, container 0.
		{PodUser: "0", User: "0", WantValue: 0, WantSet: true},
		// Test 5: Pod 0, container 1000, container wins.
		{PodUser: "0", User: "1000", WantValue: 1000, WantSet: true},
		// Test 6: Pod 1000 only.
		{PodUser: "1000", User: "-", WantValue: 1000, WantSet: true},
		// Test 7: Pod 1000, container 0, container wins.
		{PodUser: "1000", User: "0", WantValue: 0, WantSet: true},
		// Test 8: Pod 1000, container 1000.
		{PodUser: "1000", User: "1000", WantValue: 1000, WantSet: true},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			pod := testPod(t, "-", test.PodUser)
			gotValue, gotSet := RunAsUser(pod, testContainer(t, "-", test.User))
			if diff := cmp.Diff(test.WantValue, gotValue); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantSet, gotSet); diff != "" {
				t.Errorf("set mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNilPod(t *testing.T) {
	t.Parallel()
	c := corev1.Container{SecurityContext: &corev1.SecurityContext{}}
	if v, set := RunAsNonRoot(nil, c); v || set {
		t.Errorf("RunAsNonRoot(nil) = %v, %v, want false, false", v, set)
	}
	if v, set := RunAsUser(nil, c); v != 0 || set {
		t.Errorf("RunAsUser(nil) = %v, %v, want 0, false", v, set)
	}
	if got := RootStatus(nil, c); got != Unknown {
		t.Errorf("RootStatus(nil) = %q, want %q", got, Unknown)
	}
	if SeccompConfined(nil, c) {
		t.Error("SeccompConfined(nil) = true, want false")
	}
	if got := Containers(nil, true); got != nil {
		t.Errorf("Containers(nil) = %v, want nil", got)
	}
}

func TestRootStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		PodNonRoot string
		PodUser    string
		NonRoot    string
		User       string
		WantStatus Status
	}{
		// Test 0: Pod nonRoot unset user unset, container nonRoot unset user unset.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "-", User: "-", WantStatus: Unknown},
		// Test 1: Pod nonRoot unset user unset, container nonRoot unset user 0.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 2: Pod nonRoot unset user unset, container nonRoot unset user 1000.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 3: Pod nonRoot unset user unset, container nonRoot true user unset.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 4: Pod nonRoot unset user unset, container nonRoot true user 0.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 5: Pod nonRoot unset user unset, container nonRoot true user 1000.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 6: Pod nonRoot unset user unset, container nonRoot false user unset.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "f", User: "-", WantStatus: Unknown},
		// Test 7: Pod nonRoot unset user unset, container nonRoot false user 0.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 8: Pod nonRoot unset user unset, container nonRoot false user 1000.
		{PodNonRoot: "-", PodUser: "-", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 9: Pod nonRoot unset user 0, container nonRoot unset user unset.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "-", User: "-", WantStatus: Root},
		// Test 10: Pod nonRoot unset user 0, container nonRoot unset user 0.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 11: Pod nonRoot unset user 0, container nonRoot unset user 1000.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 12: Pod nonRoot unset user 0, container nonRoot true user unset.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "t", User: "-", WantStatus: Root},
		// Test 13: Pod nonRoot unset user 0, container nonRoot true user 0.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 14: Pod nonRoot unset user 0, container nonRoot true user 1000.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 15: Pod nonRoot unset user 0, container nonRoot false user unset.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "f", User: "-", WantStatus: Root},
		// Test 16: Pod nonRoot unset user 0, container nonRoot false user 0.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 17: Pod nonRoot unset user 0, container nonRoot false user 1000.
		{PodNonRoot: "-", PodUser: "0", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 18: Pod nonRoot unset user 1000, container nonRoot unset user unset.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "-", User: "-", WantStatus: NonRoot},
		// Test 19: Pod nonRoot unset user 1000, container nonRoot unset user 0.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 20: Pod nonRoot unset user 1000, container nonRoot unset user 1000.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 21: Pod nonRoot unset user 1000, container nonRoot true user unset.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 22: Pod nonRoot unset user 1000, container nonRoot true user 0.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 23: Pod nonRoot unset user 1000, container nonRoot true user 1000.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 24: Pod nonRoot unset user 1000, container nonRoot false user unset.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "f", User: "-", WantStatus: NonRoot},
		// Test 25: Pod nonRoot unset user 1000, container nonRoot false user 0.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 26: Pod nonRoot unset user 1000, container nonRoot false user 1000.
		{PodNonRoot: "-", PodUser: "1000", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 27: Pod nonRoot true user unset, container nonRoot unset user unset.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "-", User: "-", WantStatus: NonRoot},
		// Test 28: Pod nonRoot true user unset, container nonRoot unset user 0.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 29: Pod nonRoot true user unset, container nonRoot unset user 1000.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 30: Pod nonRoot true user unset, container nonRoot true user unset.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 31: Pod nonRoot true user unset, container nonRoot true user 0.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 32: Pod nonRoot true user unset, container nonRoot true user 1000.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 33: Pod nonRoot true user unset, container nonRoot false user unset.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "f", User: "-", WantStatus: Unknown},
		// Test 34: Pod nonRoot true user unset, container nonRoot false user 0.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 35: Pod nonRoot true user unset, container nonRoot false user 1000.
		{PodNonRoot: "t", PodUser: "-", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 36: Pod nonRoot true user 0, container nonRoot unset user unset.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "-", User: "-", WantStatus: Root},
		// Test 37: Pod nonRoot true user 0, container nonRoot unset user 0.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 38: Pod nonRoot true user 0, container nonRoot unset user 1000.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 39: Pod nonRoot true user 0, container nonRoot true user unset.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "t", User: "-", WantStatus: Root},
		// Test 40: Pod nonRoot true user 0, container nonRoot true user 0.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 41: Pod nonRoot true user 0, container nonRoot true user 1000.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 42: Pod nonRoot true user 0, container nonRoot false user unset.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "f", User: "-", WantStatus: Root},
		// Test 43: Pod nonRoot true user 0, container nonRoot false user 0.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 44: Pod nonRoot true user 0, container nonRoot false user 1000.
		{PodNonRoot: "t", PodUser: "0", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 45: Pod nonRoot true user 1000, container nonRoot unset user unset.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "-", User: "-", WantStatus: NonRoot},
		// Test 46: Pod nonRoot true user 1000, container nonRoot unset user 0.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 47: Pod nonRoot true user 1000, container nonRoot unset user 1000.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 48: Pod nonRoot true user 1000, container nonRoot true user unset.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 49: Pod nonRoot true user 1000, container nonRoot true user 0.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 50: Pod nonRoot true user 1000, container nonRoot true user 1000.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 51: Pod nonRoot true user 1000, container nonRoot false user unset.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "f", User: "-", WantStatus: NonRoot},
		// Test 52: Pod nonRoot true user 1000, container nonRoot false user 0.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 53: Pod nonRoot true user 1000, container nonRoot false user 1000.
		{PodNonRoot: "t", PodUser: "1000", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 54: Pod nonRoot false user unset, container nonRoot unset user unset.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "-", User: "-", WantStatus: Unknown},
		// Test 55: Pod nonRoot false user unset, container nonRoot unset user 0.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 56: Pod nonRoot false user unset, container nonRoot unset user 1000.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 57: Pod nonRoot false user unset, container nonRoot true user unset.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 58: Pod nonRoot false user unset, container nonRoot true user 0.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 59: Pod nonRoot false user unset, container nonRoot true user 1000.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 60: Pod nonRoot false user unset, container nonRoot false user unset.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "f", User: "-", WantStatus: Unknown},
		// Test 61: Pod nonRoot false user unset, container nonRoot false user 0.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 62: Pod nonRoot false user unset, container nonRoot false user 1000.
		{PodNonRoot: "f", PodUser: "-", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 63: Pod nonRoot false user 0, container nonRoot unset user unset.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "-", User: "-", WantStatus: Root},
		// Test 64: Pod nonRoot false user 0, container nonRoot unset user 0.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 65: Pod nonRoot false user 0, container nonRoot unset user 1000.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 66: Pod nonRoot false user 0, container nonRoot true user unset.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "t", User: "-", WantStatus: Root},
		// Test 67: Pod nonRoot false user 0, container nonRoot true user 0.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 68: Pod nonRoot false user 0, container nonRoot true user 1000.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 69: Pod nonRoot false user 0, container nonRoot false user unset.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "f", User: "-", WantStatus: Root},
		// Test 70: Pod nonRoot false user 0, container nonRoot false user 0.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 71: Pod nonRoot false user 0, container nonRoot false user 1000.
		{PodNonRoot: "f", PodUser: "0", NonRoot: "f", User: "1000", WantStatus: NonRoot},
		// Test 72: Pod nonRoot false user 1000, container nonRoot unset user unset.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "-", User: "-", WantStatus: NonRoot},
		// Test 73: Pod nonRoot false user 1000, container nonRoot unset user 0.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "-", User: "0", WantStatus: Root},
		// Test 74: Pod nonRoot false user 1000, container nonRoot unset user 1000.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "-", User: "1000", WantStatus: NonRoot},
		// Test 75: Pod nonRoot false user 1000, container nonRoot true user unset.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "t", User: "-", WantStatus: NonRoot},
		// Test 76: Pod nonRoot false user 1000, container nonRoot true user 0.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "t", User: "0", WantStatus: Root},
		// Test 77: Pod nonRoot false user 1000, container nonRoot true user 1000.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "t", User: "1000", WantStatus: NonRoot},
		// Test 78: Pod nonRoot false user 1000, container nonRoot false user unset.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "f", User: "-", WantStatus: NonRoot},
		// Test 79: Pod nonRoot false user 1000, container nonRoot false user 0.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "f", User: "0", WantStatus: Root},
		// Test 80: Pod nonRoot false user 1000, container nonRoot false user 1000.
		{PodNonRoot: "f", PodUser: "1000", NonRoot: "f", User: "1000", WantStatus: NonRoot},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			pod := testPod(t, test.PodNonRoot, test.PodUser)
			got := RootStatus(pod, testContainer(t, test.NonRoot, test.User))
			if diff := cmp.Diff(test.WantStatus, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSeccompConfined(t *testing.T) {
	t.Parallel()
	const (
		unset   = corev1.SeccompProfileType("")
		runtime = corev1.SeccompProfileTypeRuntimeDefault
		unconf  = corev1.SeccompProfileTypeUnconfined
		local   = corev1.SeccompProfileTypeLocalhost
	)
	tests := []struct {
		Pod        corev1.SeccompProfileType
		Container  corev1.SeccompProfileType
		WantResult bool
	}{
		// Test 0: Nothing set.
		{Pod: unset, Container: unset, WantResult: false},
		// Test 1: Container RuntimeDefault only.
		{Pod: unset, Container: runtime, WantResult: true},
		// Test 2: Container Unconfined only.
		{Pod: unset, Container: unconf, WantResult: false},
		// Test 3: Pod RuntimeDefault only.
		{Pod: runtime, Container: unset, WantResult: true},
		// Test 4: Pod RuntimeDefault, container RuntimeDefault.
		{Pod: runtime, Container: runtime, WantResult: true},
		// Test 5: Pod RuntimeDefault, container Unconfined, container wins.
		{Pod: runtime, Container: unconf, WantResult: false},
		// Test 6: Pod Unconfined only.
		{Pod: unconf, Container: unset, WantResult: false},
		// Test 7: Pod Unconfined, container RuntimeDefault, container wins.
		{Pod: unconf, Container: runtime, WantResult: true},
		// Test 8: Pod Unconfined, container Unconfined.
		{Pod: unconf, Container: unconf, WantResult: false},
		// Test 9: Container Localhost only.
		{Pod: unset, Container: local, WantResult: true},
		// Test 10: Pod Localhost, container Unconfined, container wins.
		{Pod: local, Container: unconf, WantResult: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := SeccompConfined(testSeccompPod(test.Pod), testSeccompContainer(test.Container))
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSeccompConfinedEmptyType(t *testing.T) {
	t.Parallel()
	pod := testSeccompPod(corev1.SeccompProfileTypeRuntimeDefault)
	c := corev1.Container{SecurityContext: &corev1.SecurityContext{
		SeccompProfile: &corev1.SeccompProfile{},
	}}
	if SeccompConfined(pod, c) {
		t.Error("SeccompConfined with an empty container profile type = true, want false")
	}
}

func TestAllowsPrivilegeEscalation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		SecurityContext *corev1.SecurityContext
		WantResult      bool
	}{
		// Test 0: No security context defaults to true.
		{SecurityContext: nil, WantResult: true},
		// Test 1: Field unset defaults to true.
		{SecurityContext: &corev1.SecurityContext{}, WantResult: true},
		// Test 2: Explicit false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
		}, WantResult: false},
		// Test 3: Explicit true.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(true),
		}, WantResult: true},
		// Test 4: Privileged forces true over false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Privileged:               testPtr(true),
		}, WantResult: true},
		// Test 5: Privileged false keeps false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Privileged:               testPtr(false),
		}, WantResult: false},
		// Test 6: CAP_SYS_ADMIN in adds forces true over false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"CAP_SYS_ADMIN"}},
		}, WantResult: true},
		// Test 7: SYS_ADMIN without the prefix forces true over false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"sys_admin"}},
		}, WantResult: true},
		// Test 8: ALL in adds grants CAP_SYS_ADMIN and forces true over false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"ALL"}},
		}, WantResult: true},
		// Test 9: Other adds keep false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}},
		}, WantResult: false},
		// Test 10: CAP_SYS_ADMIN in drops keeps false.
		{SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: testPtr(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"CAP_SYS_ADMIN"}},
		}, WantResult: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := AllowsPrivilegeEscalation(corev1.Container{SecurityContext: test.SecurityContext})
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReadOnlyRootFS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		SecurityContext *corev1.SecurityContext
		WantResult      bool
	}{
		// Test 0: No security context defaults to writable.
		{SecurityContext: nil, WantResult: false},
		// Test 1: Field unset defaults to writable.
		{SecurityContext: &corev1.SecurityContext{}, WantResult: false},
		// Test 2: Explicit true.
		{SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: testPtr(true),
		}, WantResult: true},
		// Test 3: Explicit false.
		{SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: testPtr(false),
		}, WantResult: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := ReadOnlyRootFS(corev1.Container{SecurityContext: test.SecurityContext})
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDropsAllCapabilities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		SecurityContext *corev1.SecurityContext
		WantResult      bool
	}{
		// Test 0: No security context.
		{SecurityContext: nil, WantResult: false},
		// Test 1: No capabilities.
		{SecurityContext: &corev1.SecurityContext{}, WantResult: false},
		// Test 2: Drops ALL.
		{SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW", "ALL"}},
		}, WantResult: true},
		// Test 3: Drops all in lower case.
		{SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"all"}},
		}, WantResult: true},
		// Test 4: Drops only some.
		{SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}},
		}, WantResult: false},
		// Test 5: ALL in adds is not a drop.
		{SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"ALL"}},
		}, WantResult: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := DropsAllCapabilities(corev1.Container{SecurityContext: test.SecurityContext})
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestContainers(t *testing.T) {
	t.Parallel()
	sc := &corev1.SecurityContext{RunAsNonRoot: testPtr(true)}
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Image: "busybox"}},
		Containers:     []corev1.Container{{Name: "app", Image: "nginx"}},
		EphemeralContainers: []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:            "debug",
				Image:           "alpine",
				Command:         []string{"sh"},
				SecurityContext: sc,
			},
			TargetContainerName: "app",
		}},
	}}
	tests := []struct {
		Pod              *corev1.Pod
		IncludeEphemeral bool
		WantResult       []corev1.Container
	}{
		// Test 0: Init and regular containers without ephemeral.
		{Pod: pod, IncludeEphemeral: false, WantResult: []corev1.Container{
			{Name: "init", Image: "busybox"},
			{Name: "app", Image: "nginx"},
		}},
		// Test 1: Ephemeral containers converted and appended when asked.
		{Pod: pod, IncludeEphemeral: true, WantResult: []corev1.Container{
			{Name: "init", Image: "busybox"},
			{Name: "app", Image: "nginx"},
			{Name: "debug", Image: "alpine", Command: []string{"sh"}, SecurityContext: sc},
		}},
		// Test 2: Empty pod yields no containers.
		{Pod: &corev1.Pod{}, IncludeEphemeral: true, WantResult: nil},
		// Test 3: Nil pod yields nil.
		{Pod: nil, IncludeEphemeral: false, WantResult: nil},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := Containers(test.Pod, test.IncludeEphemeral)
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
