package workloadcoverage

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// int32Ptr returns a pointer to n.
func int32Ptr(n int32) *int32 { return &n }

// matchLabels builds a LabelSelector matching the given labels.
func matchLabels(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

// deployment builds a Deployment with the given replica count and pod template
// labels. A nil replicas argument leaves the field unset.
func deployment(namespace, name string, replicas *int32, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: replicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}},
		},
	}
}

// statefulSet builds a StatefulSet with the given replica count and pod
// template labels.
func statefulSet(namespace, name string, replicas *int32, labels map[string]string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Replicas: replicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}},
		},
	}
}

// pdb builds a PodDisruptionBudget with the given pod selector. A nil selector
// never matches; an empty selector matches every pod in the namespace.
func pdb(namespace, name string, selector *metav1.LabelSelector) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: selector},
	}
}

// hpa builds a HorizontalPodAutoscaler targeting the named workload kind.
func hpa(namespace, kind, target string) *autoscalingv2.HorizontalPodAutoscaler {
	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: target + "-hpa"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: kind, Name: target},
		},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantData Data
		Objects  []runtime.Object
	}{{ // Test 0: No workloads yields empty data.
		Objects:  nil,
		WantData: Data{},
	}, { // Test 1: Workloads with one or fewer replicas are ignored.
		Objects: []runtime.Object{
			deployment("default", "nil-replicas", nil, map[string]string{"app": "a"}),
			deployment("default", "single", int32Ptr(1), map[string]string{"app": "b"}),
			statefulSet("default", "ss-default", nil, map[string]string{"app": "c"}),
		},
		WantData: Data{},
	}, { // Test 2: A replicated deployment with no PDB or HPA is a full gap.
		Objects: []runtime.Object{
			deployment("default", "bare", int32Ptr(3), map[string]string{"app": "bare"}),
		},
		WantData: Data{
			TotalReplicated: 1,
			MissingPDB:      1,
			MissingHPA:      1,
			Gaps: []Coverage{
				{Kind: "Deployment", Namespace: "default", Name: "bare", Replicas: 3},
			},
		},
	}, { // Test 3: A fully covered replicated deployment produces no gap.
		Objects: []runtime.Object{
			deployment("default", "api", int32Ptr(4), map[string]string{"app": "api"}),
			pdb("default", "api-pdb", matchLabels(map[string]string{"app": "api"})),
			hpa("default", "Deployment", "api"),
		},
		WantData: Data{TotalReplicated: 1},
	}, { // Test 4: Mixed deployment and statefulset with partial coverage, sorted.
		Objects: []runtime.Object{
			deployment("prod", "web", int32Ptr(3), map[string]string{"app": "web"}),
			pdb("prod", "web-pdb", matchLabels(map[string]string{"app": "web"})),
			statefulSet("prod", "db", int32Ptr(2), map[string]string{"app": "db"}),
			hpa("prod", "StatefulSet", "db"),
			deployment("prod", "cache", int32Ptr(1), map[string]string{"app": "cache"}),
		},
		WantData: Data{
			TotalReplicated: 2,
			MissingPDB:      1,
			MissingHPA:      1,
			Gaps: []Coverage{
				{Kind: "StatefulSet", Namespace: "prod", Name: "db", Replicas: 2, HasHPA: true},
				{Kind: "Deployment", Namespace: "prod", Name: "web", Replicas: 3, HasPDB: true},
			},
		},
	}, { // Test 5: An empty PDB selector matches all; a nil selector matches none.
		Objects: []runtime.Object{
			deployment("team", "empty-sel", int32Ptr(2), map[string]string{"app": "whatever"}),
			pdb("team", "match-all", &metav1.LabelSelector{}),
			deployment("team2", "nil-sel", int32Ptr(2), map[string]string{"app": "x"}),
			pdb("team2", "broken", nil),
		},
		WantData: Data{
			TotalReplicated: 2,
			MissingPDB:      1,
			MissingHPA:      2,
			Gaps: []Coverage{
				{Kind: "Deployment", Namespace: "team", Name: "empty-sel", Replicas: 2, HasPDB: true},
				{Kind: "Deployment", Namespace: "team2", Name: "nil-sel", Replicas: 2},
			},
		},
	}, { // Test 6: A PDB with an invalid selector is skipped, leaving a gap.
		Objects: []runtime.Object{
			deployment("edge", "bad-sel", int32Ptr(2), map[string]string{"app": "z"}),
			pdb("edge", "broken", &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: "InvalidOp"},
				},
			}),
		},
		WantData: Data{
			TotalReplicated: 1,
			MissingPDB:      1,
			MissingHPA:      1,
			Gaps: []Coverage{
				{Kind: "Deployment", Namespace: "edge", Name: "bad-sel", Replicas: 2},
			},
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset(test.Objects...)
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
