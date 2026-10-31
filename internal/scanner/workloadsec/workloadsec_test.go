package workloadsec

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// boolPtr returns a pointer to b.
func boolPtr(b bool) *bool { return &b }

// int64Ptr returns a pointer to n.
func int64Ptr(n int64) *int64 { return &n }

// lockedPod builds a pod in namespace "a" whose single container trips no security checks, so
// the supplied pod-level security context alone drives the root-status result.
func lockedPod(name string, podSC *corev1.PodSecurityContext) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: name},
		Spec: corev1.PodSpec{
			ServiceAccountName: "svc",
			SecurityContext:    podSC,
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: boolPtr(false),
					ReadOnlyRootFilesystem:   boolPtr(true),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
			}},
		},
	}
}

// lockedContainerPod builds a pod whose single container trips no capability, escalation, or
// filesystem check, so the given pod and container security contexts alone drive the root and
// seccomp results.
func lockedContainerPod(name string, podSC *corev1.PodSecurityContext, sc *corev1.SecurityContext) *corev1.Pod {
	pod := lockedPod(name, podSC)
	locked := pod.Spec.Containers[0].SecurityContext
	locked.RunAsUser, locked.RunAsNonRoot = sc.RunAsUser, sc.RunAsNonRoot
	if sc.SeccompProfile != nil {
		locked.SeccompProfile = sc.SeccompProfile
	}
	return pod
}

// TestNewScanner checks the counts and the risky pod list the scanner builds from pods.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantData Data
		Pods     []*corev1.Pod
	}{{ // Test 0: No pods yields empty data.
		Pods:     nil,
		WantData: Data{},
	}, { // Test 1: A hardened pod trips none of the security checks.
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "hardened"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "restricted-sa",
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged:               boolPtr(false),
						RunAsNonRoot:             boolPtr(true),
						AllowPrivilegeEscalation: boolPtr(false),
						ReadOnlyRootFilesystem:   boolPtr(true),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
				}},
			},
		}},
		WantData: Data{TotalPods: 1, BaselineContainers: 1, RunAsNonRootContainers: 1},
	}, { // Test 2: A privileged host pod trips every check and is high risk.
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "privileged"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				HostPID:     true,
				HostIPC:     true,
				Volumes: []corev1.Volume{{
					Name:         "host-root",
					VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}},
				}},
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged:   boolPtr(true),
						RunAsUser:    int64Ptr(0),
						Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
					},
				}},
			},
		}},
		WantData: Data{
			TotalPods:                 1,
			BaselineContainers:        1,
			PrivilegedContainers:      1,
			HostNetworkPods:           1,
			HostPIDPods:               1,
			HostIPCPods:               1,
			HostPathVolumes:           1,
			RunAsRootContainers:       1,
			CapabilityAdditions:       1,
			MissingCapabilityDropAll:  1,
			AllowPrivilegeEscalation:  1,
			MissingSeccompProfile:     1,
			NoReadOnlyRoot:            1,
			DefaultServiceAccountPods: 1,
			HighRiskPods: []PodRisk{{
				Namespace: "prod",
				Pod:       "privileged",
				Container: "app",
				Risks: []string{
					"privileged",
					"runs-as-root",
					"capabilities-add:[NET_ADMIN]",
					"allow-privilege-escalation",
					"writable-root-fs",
					"host-network",
					"host-pid",
					"host-ipc",
				},
			}},
		},
	}, { // Test 3: A container with no security context reports unknown root.
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "undeclared"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "default",
				Containers:         []corev1.Container{{Name: "app"}},
			},
		}},
		WantData: Data{
			TotalPods:                 1,
			BaselineContainers:        1,
			RunAsUnknownContainers:    1,
			MissingCapabilityDropAll:  1,
			AllowPrivilegeEscalation:  1,
			MissingSeccompProfile:     1,
			NoReadOnlyRoot:            1,
			DefaultServiceAccountPods: 1,
			HighRiskPods: []PodRisk{{
				Namespace: "dev",
				Pod:       "undeclared",
				Container: "app",
				Risks:     []string{"allow-privilege-escalation", "writable-root-fs"},
			}},
		},
	}, { // Test 4: An ephemeral container is in the risk list but not the baseline counts.
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "nonroot"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "svc",
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				Containers: []corev1.Container{{
					Name:            "main",
					SecurityContext: &corev1.SecurityContext{RunAsUser: int64Ptr(1000)},
				}},
				EphemeralContainers: []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name:            "debug",
						SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(false)},
					},
				}},
			},
		}},
		WantData: Data{
			TotalPods:                1,
			BaselineContainers:       1,
			RunAsNonRootContainers:   1,
			MissingCapabilityDropAll: 2,
			AllowPrivilegeEscalation: 1,
			NoReadOnlyRoot:           1,
			HighRiskPods: []PodRisk{{
				Namespace: "app",
				Pod:       "nonroot",
				Container: "debug",
				Risks:     []string{"allow-privilege-escalation", "writable-root-fs"},
			}, {
				Namespace: "app",
				Pod:       "nonroot",
				Container: "main",
				Risks:     []string{"allow-privilege-escalation", "writable-root-fs"},
			}},
		},
	}, { // Test 5: A pod-level run-as-user of zero makes the container root.
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "podroot"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "svc",
				SecurityContext:    &corev1.PodSecurityContext{RunAsUser: int64Ptr(0)},
				Containers: []corev1.Container{{
					Name: "main",
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(false),
						ReadOnlyRootFilesystem:   boolPtr(true),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
				}},
			},
		}},
		WantData: Data{
			TotalPods:           1,
			BaselineContainers:  1,
			RunAsRootContainers: 1,
		},
	}, { // Test 6: Pod-level user settings drive root status, and runAsNonRoot false is unknown.
		Pods: []*corev1.Pod{
			lockedPod("pod-nonroot-user", &corev1.PodSecurityContext{RunAsUser: int64Ptr(2000)}),
			lockedPod("pod-nonroot-flag", &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}),
			lockedPod("pod-root-flag", &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(false)}),
		},
		WantData: Data{
			TotalPods:              3,
			BaselineContainers:     3,
			RunAsNonRootContainers: 2,
			RunAsUnknownContainers: 1,
		},
	}, { // Test 7: Container settings win over pod settings for root status and seccomp.
		Pods: []*corev1.Pod{
			lockedContainerPod("nonroot-under-pod-root",
				&corev1.PodSecurityContext{RunAsUser: int64Ptr(0)},
				&corev1.SecurityContext{RunAsNonRoot: boolPtr(true)}),
			lockedContainerPod("false-under-pod-true",
				&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
				&corev1.SecurityContext{RunAsNonRoot: boolPtr(false)}),
			lockedContainerPod("unconfined-under-pod-default",
				&corev1.PodSecurityContext{
					RunAsUser:      int64Ptr(1000),
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
				&corev1.SecurityContext{
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
				}),
		},
		WantData: Data{
			TotalPods:              3,
			BaselineContainers:     3,
			RunAsRootContainers:    1,
			RunAsNonRootContainers: 1,
			RunAsUnknownContainers: 1,
			MissingSeccompProfile:  1,
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			objs := make([]runtime.Object, 0, len(test.Pods))
			for _, p := range test.Pods {
				objs = append(objs, p)
			}
			cs := fakeclientset.NewSimpleClientset(objs...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}

			if diff := cmp.Diff(test.WantData, data, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestScanListError verifies a pod list failure is wrapped as scanner.ErrScan.
func TestScanListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("boom")
		})
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected scanner.ErrScan, got %v", err)
	}
}

// TestScanForbiddenIsErrored verifies a denied pod list is a blind, errored read rather than a
// cluster with zero risky pods.
func TestScanForbiddenIsErrored(t *testing.T) {
	t.Parallel()
	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac denied"))
	})
	result, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithClientset("test", cs))
	if !errors.Is(err, scanner.ErrScan) || !apierrors.IsForbidden(err) {
		t.Fatalf("err = %v, want ErrScan wrapping Forbidden", err)
	}
	if result.State != scanner.StateErrored || result.Data != nil {
		t.Errorf("result = %+v, want errored with no data", result)
	}
}

// TestTopNPermutation verifies the fifty high-risk pods the scanner keeps do not depend on input
// order when sixty containers tie on risk count. The fake clientset always lists in one order,
// so the test shuffles the items itself.
func TestTopNPermutation(t *testing.T) {
	t.Parallel()
	items := make([]PodRisk, 0, 60)
	for i := range 60 {
		items = append(items, PodRisk{
			Namespace: fmt.Sprintf("ns-%d", i/30),
			Pod:       fmt.Sprintf("pod-%d", i/3%10),
			Container: fmt.Sprintf("c-%d", i%3),
			Risks:     []string{"privileged"},
		})
	}
	rng := rand.New(rand.NewPCG(1, 2))
	first := scanner.TopN(slices.Clone(items), 50, comparePodRisks)
	for run := range 20 {
		shuffled := slices.Clone(items)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		if diff := cmp.Diff(first, scanner.TopN(shuffled, 50, comparePodRisks)); diff != "" {
			t.Fatalf("shuffle %d differs (-first +got):\n%s", run, diff)
		}
	}
}
