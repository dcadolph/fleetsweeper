package scanner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// pagedPods serves pods from a fake clientset in pages of the given names, handing out a
// continue token per page and recording the options of every list call. expireOnce makes the
// first continued request fail with 410 Gone, and expireAlways makes every one fail.
type pagedPods struct {
	// pages lists the pod names on each page.
	pages [][]string
	// expireOnce fails the first continued request with an expired token.
	expireOnce bool
	// expireAlways fails every continued request with an expired token.
	expireAlways bool
	// repeatToken makes every page return the same continue token.
	repeatToken bool
	// calls records the ListOptions of each request.
	calls []metav1.ListOptions
}

// clientset returns a fake clientset whose pod list is served by p.
func (p *pagedPods) clientset() *fakeclientset.Clientset {
	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		opts := a.(clienttesting.ListActionImpl).GetListOptions()
		p.calls = append(p.calls, opts)
		page := 0
		if opts.Continue != "" {
			if p.expireAlways || p.expireOnce {
				p.expireOnce = false
				return true, nil, apierrors.NewResourceExpired("continue token expired")
			}
			if _, err := fmt.Sscanf(opts.Continue, "page-%d", &page); err != nil {
				return true, nil, err
			}
		}
		list := &corev1.PodList{}
		for _, name := range p.pages[page] {
			list.Items = append(list.Items, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}})
		}
		if page+1 < len(p.pages) {
			list.Continue = fmt.Sprintf("page-%d", page+1)
		}
		if p.repeatToken {
			list.Continue = "page-0"
		}
		return true, list, nil
	})
	return cs
}

// listPodNames runs ListAll over cs with opts and returns the pod names.
func listPodNames(cs *fakeclientset.Clientset, opts metav1.ListOptions) ([]string, error) {
	pods, err := ListAll(context.Background(), opts, cs.CoreV1().Pods("").List,
		func(l *corev1.PodList) []corev1.Pod { return l.Items })
	if err != nil {
		return nil, err
	}
	names := make([]string, len(pods))
	for i, p := range pods {
		names[i] = p.Name
	}
	return names, nil
}

// TestListAllPages verifies ListAll follows continue tokens across pages, keeps selectors and
// the limit on every page, drops the resource version from continued pages, and restarts once
// on an expired token.
func TestListAllPages(t *testing.T) {
	t.Parallel()
	cached := CacheReadOptions()
	cached.FieldSelector = "type=kubernetes.io/tls"
	firstPage := metav1.ListOptions{
		Limit: DefaultListLimit, ResourceVersion: "0", ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		FieldSelector: "type=kubernetes.io/tls",
	}
	continued := func(token string) metav1.ListOptions {
		return metav1.ListOptions{Limit: DefaultListLimit, FieldSelector: "type=kubernetes.io/tls", Continue: token}
	}
	tests := []struct {
		Pager     *pagedPods
		Opts      metav1.ListOptions
		Want      error
		WantNames []string
		WantCalls []metav1.ListOptions
	}{{ // Test 0: Three pages arrive in order and continued pages carry no resource version.
		Pager: &pagedPods{pages: [][]string{{"a", "b"}, {"c"}, {"d"}}}, Opts: cached,
		WantNames: []string{"a", "b", "c", "d"},
		WantCalls: []metav1.ListOptions{firstPage, continued("page-1"), continued("page-2")},
	}, { // Test 1: One page is one call.
		Pager: &pagedPods{pages: [][]string{{"a"}}}, Opts: cached,
		WantNames: []string{"a"}, WantCalls: []metav1.ListOptions{firstPage},
	}, { // Test 2: A caller-set limit is kept on every page.
		Pager: &pagedPods{pages: [][]string{{"a"}, {"b"}}}, Opts: metav1.ListOptions{Limit: 7},
		WantNames: []string{"a", "b"},
		WantCalls: []metav1.ListOptions{{Limit: 7}, {Limit: 7, Continue: "page-1"}},
	}, { // Test 3: An expired token restarts the list once and drops the partial first pass.
		Pager: &pagedPods{pages: [][]string{{"a"}, {"b"}}, expireOnce: true}, Opts: cached,
		WantNames: []string{"a", "b"},
		WantCalls: []metav1.ListOptions{firstPage, continued("page-1"), firstPage, continued("page-1")},
	}, { // Test 4: A token that expires again after the restart is returned as an error.
		Pager: &pagedPods{pages: [][]string{{"a"}, {"b"}}, expireAlways: true}, Opts: cached,
		Want:      errExpired,
		WantCalls: []metav1.ListOptions{firstPage, continued("page-1"), firstPage, continued("page-1")},
	}, { // Test 5: A server that repeats its continue token is an error, not an endless loop.
		Pager: &pagedPods{pages: [][]string{{"a"}, {"b"}}, repeatToken: true}, Opts: cached,
		Want:      errRepeated,
		WantCalls: []metav1.ListOptions{firstPage, continued("page-0")},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			names, err := listPodNames(test.Pager.clientset(), test.Opts)
			switch {
			case test.Want == errExpired:
				if !apierrors.IsResourceExpired(err) {
					t.Errorf("want an expired error, got %v", err)
				}
			case test.Want == errRepeated:
				if err == nil {
					t.Error("want an error for a repeated continue token")
				}
			case err != nil:
				t.Fatalf("ListAll: %v", err)
			}
			if diff := cmp.Diff(test.WantNames, names, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("names mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCalls, test.Pager.calls); diff != "" {
				t.Errorf("list options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Sentinels that select an error check in TestListAllPages.
var (
	errExpired  = errors.New("expired")
	errRepeated = errors.New("repeated")
)

// TestListAllFirstPageError verifies a failed first page returns the server's error untouched,
// so ClassifyError still sees it.
func TestListAllFirstPageError(t *testing.T) {
	t.Parallel()
	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), "", errors.New("denied"))
	})
	_, err := listPodNames(cs, CacheReadOptions())
	if !apierrors.IsForbidden(err) {
		t.Fatalf("want Forbidden, got %v", err)
	}
}
