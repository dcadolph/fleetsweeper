package scanner

import (
	"context"
	"time"

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

// ListPager paginates an apiserver list call using Continue tokens and the
// supplied list function. The list function should call the typed client's
// List method with the provided options and return the raw list result; the
// caller is responsible for appending each page's items into its accumulator
// inside the callback. ResourceVersion is fixed at "0" with NotOlderThan
// match semantics so reads come from the apiserver watch cache rather than
// etcd, dramatically reducing load on large clusters.
type ListPager func(ctx context.Context, opts metav1.ListOptions) (continueToken string, err error)

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

// ListAll drives a ListPager to completion, applying a per-list timeout and
// the watch-cache hint described above. The list function is invoked once per
// page; pagination stops when the apiserver returns an empty continue token.
func ListAll(ctx context.Context, list ListPager) error {
	opts := metav1.ListOptions{
		Limit:                DefaultListLimit,
		ResourceVersion:      "0",
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
	}
	for {
		listCtx, cancel := context.WithTimeout(ctx, DefaultListTimeout)
		token, err := list(listCtx, opts)
		cancel()
		if err != nil {
			return err
		}
		if token == "" {
			return nil
		}
		opts.Continue = token
	}
}
