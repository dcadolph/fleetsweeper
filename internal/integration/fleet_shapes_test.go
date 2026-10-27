//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// normQuotaCPU is the CPU quota every norm namespace carries.
	normQuotaCPU = "20"
	// outlierQuotaCPU is the outlier's ledger quota, an order of magnitude off the norm.
	outlierQuotaCPU = "200"
	// outlierBinding grants cluster-admin to unauthenticated users on the outlier only.
	outlierBinding = "fs-anonymous-admin"
	// defaultDeny is the name of the default-deny NetworkPolicy in each norm namespace.
	defaultDeny = "default-deny"
	// readerRole is the ClusterRole and ServiceAccount name every cluster shares.
	readerRole = "fleetsweeper-reader"
	// normCRD is the CRD every cluster has.
	normCRD = "widgets.example.com"
	// orphanCRD is the CRD only the outlier has.
	orphanCRD = "gadgets.example.com"
	// outlierNoPolicyNS loses its default-deny policy on the outlier.
	outlierNoPolicyNS = "payments"
	// outlierQuotaNS gets the outlier quota.
	outlierQuotaNS = "ledger"
)

// normNamespaces are the application namespaces every cluster shares.
var normNamespaces = []string{"payments", "ledger", "edge-ingress"} //nolint:gochecknoglobals // Not modified.

// shapeClients holds the clients a seeder needs for one cluster.
type shapeClients struct {
	// Core is the typed Kubernetes clientset.
	Core kubernetes.Interface
	// Ext is the apiextensions clientset for CRDs.
	Ext apiextclient.Interface
}

// shapeClientsFor returns the seeding clients for cluster i of the fleet.
func (f *fleet) shapeClientsFor(t *testing.T, i int) shapeClients {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: f.kubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: f.Contexts()[i]},
	).ClientConfig()
	if err != nil {
		t.Fatalf("rest config for cluster %d: %v", i+1, err)
	}
	ext, err := apiextclient.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("apiextensions client for cluster %d: %v", i+1, err)
	}
	return shapeClients{Core: f.Clientset(i), Ext: ext}
}

// seedNorm applies the shape every norm cluster shares: three namespaces, each with a
// 20 CPU quota and a default-deny policy, a reader ClusterRole bound to a ServiceAccount,
// the widgets CRD, and the site ConfigMap the geo scanner reads. It is idempotent and
// returns once every object is listable.
func seedNorm(ctx context.Context, t *testing.T, c shapeClients) {
	t.Helper()
	for _, ns := range normNamespaces {
		ensure(t, "namespace "+ns, func() error {
			_, err := c.Core.CoreV1().Namespaces().Create(ctx,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
			return err
		})
		applyQuota(ctx, t, c, ns, normQuotaCPU)
		applyDefaultDeny(ctx, t, c, ns)
	}
	ensure(t, "service account", func() error {
		_, err := c.Core.CoreV1().ServiceAccounts("edge-ingress").Create(ctx,
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: readerRole}}, metav1.CreateOptions{})
		return err
	})
	ensure(t, "cluster role", func() error {
		_, err := c.Core.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: readerRole},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"},
			}},
		}, metav1.CreateOptions{})
		return err
	})
	ensure(t, "cluster role binding", func() error {
		_, err := c.Core.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: readerRole},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: readerRole},
			Subjects: []rbacv1.Subject{{
				Kind: rbacv1.ServiceAccountKind, Name: readerRole, Namespace: "edge-ingress",
			}},
		}, metav1.CreateOptions{})
		return err
	})
	applyCRD(ctx, t, c, "widgets", "Widget")
	ensure(t, "site configmap", func() error {
		_, err := c.Core.CoreV1().ConfigMaps("kube-system").Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "fleetsweeper"},
			Data:       map[string]string{"lat": "30.27", "lng": "-97.74", "site": "kind-local"},
		}, metav1.CreateOptions{})
		return err
	})
	waitListable(ctx, t, "norm", func() (bool, error) {
		for _, ns := range normNamespaces {
			if _, err := c.Core.NetworkingV1().NetworkPolicies(ns).Get(ctx, defaultDeny, metav1.GetOptions{}); err != nil {
				return false, nil
			}
			if _, err := c.Core.CoreV1().ResourceQuotas(ns).Get(ctx, "compute", metav1.GetOptions{}); err != nil {
				return false, nil
			}
		}
		return crdEstablished(ctx, c, normCRD)
	})
}

// seedOutlier applies the norm, then the outlier's differences: cluster-admin bound to
// system:unauthenticated, no default-deny policy in payments, a 200 CPU quota in ledger,
// and the gadgets CRD no other cluster has. It is idempotent and returns once every
// difference is listable.
func seedOutlier(ctx context.Context, t *testing.T, c shapeClients) {
	t.Helper()
	seedNorm(ctx, t, c)
	ensure(t, "outlier binding", func() error {
		_, err := c.Core.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: outlierBinding},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{
				Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:unauthenticated",
			}},
		}, metav1.CreateOptions{})
		return err
	})
	deleteIgnoringMissing(t, "payments default-deny", func() error {
		return c.Core.NetworkingV1().NetworkPolicies(outlierNoPolicyNS).Delete(ctx, defaultDeny, metav1.DeleteOptions{})
	})
	applyQuota(ctx, t, c, outlierQuotaNS, outlierQuotaCPU)
	applyCRD(ctx, t, c, "gadgets", "Gadget")
	waitListable(ctx, t, "outlier", func() (bool, error) {
		if _, err := c.Core.RbacV1().ClusterRoleBindings().Get(ctx, outlierBinding, metav1.GetOptions{}); err != nil {
			return false, nil
		}
		_, err := c.Core.NetworkingV1().NetworkPolicies(outlierNoPolicyNS).Get(ctx, defaultDeny, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			return false, nil
		}
		q, err := c.Core.CoreV1().ResourceQuotas(outlierQuotaNS).Get(ctx, "compute", metav1.GetOptions{})
		if err != nil || quotaCPU(q) != outlierQuotaCPU {
			return false, nil
		}
		return crdEstablished(ctx, c, orphanCRD)
	})
}

// fixOutlier removes the outlier's privileged binding and restores its default-deny
// policy, leaving the quota and the orphan CRD in place.
func fixOutlier(ctx context.Context, t *testing.T, c shapeClients) {
	t.Helper()
	deleteIgnoringMissing(t, "outlier binding", func() error {
		return c.Core.RbacV1().ClusterRoleBindings().Delete(ctx, outlierBinding, metav1.DeleteOptions{})
	})
	applyDefaultDeny(ctx, t, c, outlierNoPolicyNS)
	waitListable(ctx, t, "fixed outlier", func() (bool, error) {
		_, err := c.Core.RbacV1().ClusterRoleBindings().Get(ctx, outlierBinding, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			return false, nil
		}
		_, err = c.Core.NetworkingV1().NetworkPolicies(outlierNoPolicyNS).Get(ctx, defaultDeny, metav1.GetOptions{})
		return err == nil, nil
	})
}

// applyQuota creates or updates the compute quota in ns with the given CPU limit.
func applyQuota(ctx context.Context, t *testing.T, c shapeClients, ns, cpu string) {
	t.Helper()
	want := corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(cpu)}
	quotas := c.Core.CoreV1().ResourceQuotas(ns)
	q, err := quotas.Get(ctx, "compute", metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = quotas.Create(ctx, &corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{Name: "compute"},
			Spec:       corev1.ResourceQuotaSpec{Hard: want},
		}, metav1.CreateOptions{})
	case err == nil:
		q.Spec.Hard = want
		_, err = quotas.Update(ctx, q, metav1.UpdateOptions{})
	}
	if err != nil {
		t.Fatalf("apply quota %s/compute: %v", ns, err)
	}
}

// quotaCPU returns the requests.cpu limit of a quota, the field the shapes set.
func quotaCPU(q *corev1.ResourceQuota) string {
	v := q.Spec.Hard[corev1.ResourceRequestsCPU]
	return v.String()
}

// applyDefaultDeny creates the default-deny NetworkPolicy in ns if it is missing.
func applyDefaultDeny(ctx context.Context, t *testing.T, c shapeClients, ns string) {
	t.Helper()
	ensure(t, ns+" default-deny", func() error {
		_, err := c.Core.NetworkingV1().NetworkPolicies(ns).Create(ctx, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: defaultDeny},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		}, metav1.CreateOptions{})
		return err
	})
}

// applyCRD creates a namespaced example.com CRD with the given plural and kind if it is
// missing.
func applyCRD(ctx context.Context, t *testing.T, c shapeClients, plural, kind string) {
	t.Helper()
	preserve := true
	ensure(t, "crd "+plural, func() error {
		_, err := c.Ext.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, &apiextv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: plural + ".example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{Plural: plural, Kind: kind},
				Scope: apiextv1.NamespaceScoped,
				Versions: []apiextv1.CustomResourceDefinitionVersion{{
					Name: "v1", Served: true, Storage: true,
					Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
						Type: "object", XPreserveUnknownFields: &preserve,
					}},
				}},
			},
		}, metav1.CreateOptions{})
		return err
	})
}

// crdEstablished reports whether the named CRD exists and is Established.
func crdEstablished(ctx context.Context, c shapeClients, name string) (bool, error) {
	crd, err := c.Ext.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false, nil
	}
	for _, cond := range crd.Status.Conditions {
		if cond.Type == apiextv1.Established && cond.Status == apiextv1.ConditionTrue {
			return true, nil
		}
	}
	return false, nil
}

// ensure runs a create and treats AlreadyExists as success, so seeding is idempotent.
func ensure(t *testing.T, what string, create func() error) {
	t.Helper()
	if err := create(); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %s: %v", what, err)
	}
}

// deleteIgnoringMissing runs a delete and treats NotFound as success.
func deleteIgnoringMissing(t *testing.T, what string, del func() error) {
	t.Helper()
	if err := del(); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("delete %s: %v", what, err)
	}
}

// waitListable polls cond until it holds or a minute passes.
func waitListable(ctx context.Context, t *testing.T, what string, cond func() (bool, error)) {
	t.Helper()
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true,
		func(context.Context) (bool, error) { return cond() })
	if err != nil {
		t.Fatalf("wait for %s shape: %v", what, err)
	}
}

// shapeOf is what TestFleetShapes reads back from one cluster.
type shapeOf struct {
	// HasBinding is true when the outlier binding exists.
	HasBinding bool
	// HasPaymentsPolicy is true when payments has its default-deny policy.
	HasPaymentsPolicy bool
	// LedgerCPU is the ledger quota's CPU limit.
	LedgerCPU string
	// HasOrphanCRD is true when the gadgets CRD exists.
	HasOrphanCRD bool
}

// readShape reads back the four objects the norm and outlier differ on.
func readShape(ctx context.Context, t *testing.T, c shapeClients) shapeOf {
	t.Helper()
	var s shapeOf
	_, err := c.Core.RbacV1().ClusterRoleBindings().Get(ctx, outlierBinding, metav1.GetOptions{})
	s.HasBinding = err == nil
	_, err = c.Core.NetworkingV1().NetworkPolicies(outlierNoPolicyNS).Get(ctx, defaultDeny, metav1.GetOptions{})
	s.HasPaymentsPolicy = err == nil
	if q, err := c.Core.CoreV1().ResourceQuotas(outlierQuotaNS).Get(ctx, "compute", metav1.GetOptions{}); err == nil {
		s.LedgerCPU = quotaCPU(q)
	}
	_, err = c.Ext.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, orphanCRD, metav1.GetOptions{})
	s.HasOrphanCRD = err == nil
	return s
}

// TestFleetShapes seeds one cluster as norm and one as outlier, reads both back, then
// fixes the outlier and checks only the binding and policy changed.
func TestFleetShapes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	f := newFleet(t, "", "")
	ctx := t.Context()
	norm, outlier := f.shapeClientsFor(t, 0), f.shapeClientsFor(t, 1)
	seedNorm(ctx, t, norm)
	seedOutlier(ctx, t, outlier)
	seedOutlier(ctx, t, outlier)

	wantNorm := shapeOf{HasPaymentsPolicy: true, LedgerCPU: normQuotaCPU}
	wantOutlier := shapeOf{HasBinding: true, LedgerCPU: outlierQuotaCPU, HasOrphanCRD: true}
	wantFixed := shapeOf{HasPaymentsPolicy: true, LedgerCPU: outlierQuotaCPU, HasOrphanCRD: true}
	check := func(name string, want shapeOf, c shapeClients) {
		t.Helper()
		if got := readShape(ctx, t, c); got != want {
			t.Errorf("%s shape: want %+v, got %+v", name, want, got)
		}
	}
	check("norm", wantNorm, norm)
	check("outlier", wantOutlier, outlier)
	fixOutlier(ctx, t, outlier)
	check("fixed outlier", wantFixed, outlier)
	check("norm after fix", wantNorm, norm)
	t.Logf("shapes verified on %s", fmt.Sprint(f.Contexts()))
}
