package scanner

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultListLimit is the per-page size used by ListAll for scanner lists.
// Five hundred is the upstream client-go default for paginated lists and gives
// a reasonable tradeoff between request count and memory pressure on the
// apiserver.
const DefaultListLimit = 500

// DefaultListTimeout caps each individual list call so a slow apiserver cannot
// hang a full fleet sweep on one bad cluster.
const DefaultListTimeout = 30 * time.Second

// CacheReadOptions returns ListOptions configured to read from the apiserver
// watch cache. Use these for any read that does not need a strict-consistency
// guarantee against etcd; on a busy cluster this is an order-of-magnitude
// reduction in apiserver load. Scanners can also extend the returned options
// with their own FieldSelector or LabelSelector when needed.
func CacheReadOptions() metav1.ListOptions {
	return metav1.ListOptions{
		ResourceVersion:      "0",
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
	}
}

// ListPage is one page of a list response, typed or unstructured, that can name the next page.
type ListPage interface {
	// GetContinue returns the token for the next page, or "" on the last page.
	GetContinue() string
}

// ListAll pages through a cluster-wide list and returns every item. list is the client's List
// method, for example clientset.CoreV1().Secrets("").List or dyn.Resource(gvr).List, and items
// extracts a page's items. opts is the first request: pass CacheReadOptions to read from the
// watch cache, plus any selectors. A zero Limit becomes DefaultListLimit. Later pages carry the
// continue token and the selectors but no resource version, which the apiserver rejects
// alongside a token. Each page gets DefaultListTimeout. A continue token that expires mid-list
// restarts the list once from the first page.
func ListAll[L ListPage, T any](ctx context.Context, opts metav1.ListOptions,
	list func(context.Context, metav1.ListOptions) (L, error), items func(L) []T) ([]T, error) {
	if opts.Limit == 0 {
		opts.Limit = DefaultListLimit
	}
	var out []T
	page := opts
	restarted := false
	for {
		listCtx, cancel := context.WithTimeout(ctx, DefaultListTimeout)
		resp, err := list(listCtx, page)
		cancel()
		if err != nil {
			if page.Continue != "" && !restarted && apierrors.IsResourceExpired(err) {
				restarted = true
				out = out[:0]
				page = opts
				continue
			}
			return nil, err
		}
		out = append(out, items(resp)...)
		token := resp.GetContinue()
		if token == "" {
			return out, nil
		}
		if token == page.Continue {
			return nil, fmt.Errorf("list: server repeated continue token after %d items", len(out))
		}
		page = opts
		page.Continue = token
		page.ResourceVersion = ""
		page.ResourceVersionMatch = ""
	}
}
