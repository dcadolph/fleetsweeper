package scanner

import "slices"

// TopN sorts items in place by cmp and returns at most the first n. The sort is stable, so items
// cmp ranks equal keep their input order. Callers give cmp a full tie-break so the result does
// not depend on the order the API listed the objects in.
func TopN[T any](items []T, n int, cmp func(a, b T) int) []T {
	slices.SortStableFunc(items, cmp)
	if len(items) > n {
		return items[:n]
	}
	return items
}
