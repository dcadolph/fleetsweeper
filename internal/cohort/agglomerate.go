package cohort

import "math"

// agglomerate runs average-linkage agglomerative clustering on profiles and
// returns a per-profile group index in [0, K). K is chosen automatically from
// the largest gap in the merge-distance sequence, then clamped to [2, maxK].
// When fewer than two distinct points are present, every profile lands in
// group 0.
func agglomerate(profiles []ClusterProfile, maxK int) []int {
	n := len(profiles)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return []int{0}
	}
	if maxK < 2 {
		maxK = 2
	}

	dist := pairwiseDistances(profiles)
	merges := buildDendrogram(n, dist)

	k := chooseK(merges, maxK, n)
	return cutDendrogram(merges, n, k)
}

// pairwiseDistances builds an n x n Euclidean distance matrix.
func pairwiseDistances(profiles []ClusterProfile) [][]float64 {
	n := len(profiles)
	d := make([][]float64, n)
	for i := range d {
		d[i] = make([]float64, n)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			v := euclidean(profiles[i].Features, profiles[j].Features)
			d[i][j] = v
			d[j][i] = v
		}
	}
	return d
}

// euclidean returns the Euclidean distance between two equal-length vectors.
// When lengths differ the shorter vector is treated as zero-padded.
func euclidean(a, b []float64) float64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	var sum float64
	for i := 0; i < n; i++ {
		var av, bv float64
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		diff := av - bv
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

// merge records one step in the agglomerative dendrogram.
type merge struct {
	// a and b are the cluster indices that were merged. After merging, the
	// surviving cluster takes index n + step, where step is the position in
	// the merges slice. This matches scipy linkage-matrix conventions.
	a, b int
	// dist is the average-linkage distance between the merged clusters.
	dist float64
}

// buildDendrogram performs n-1 merges using average-linkage updates between
// clusters. Distances between the new cluster and every remaining cluster are
// updated with the Lance-Williams formula for average linkage.
func buildDendrogram(n int, dist [][]float64) []merge {
	// active[i] is true while cluster i has not been merged into another.
	active := make([]bool, 2*n-1)
	size := make([]int, 2*n-1)
	for i := 0; i < n; i++ {
		active[i] = true
		size[i] = 1
	}
	// d holds pairwise distances between cluster ids. It grows as new
	// clusters are created. Symmetric, zero on the diagonal.
	d := make(map[int]map[int]float64, 2*n-1)
	for i := 0; i < n; i++ {
		d[i] = make(map[int]float64, n-1)
		for j := 0; j < n; j++ {
			if i != j {
				d[i][j] = dist[i][j]
			}
		}
	}

	merges := make([]merge, 0, n-1)
	for step := 0; step < n-1; step++ {
		a, b, best := -1, -1, math.MaxFloat64
		for i := range active {
			if !active[i] {
				continue
			}
			for j, v := range d[i] {
				if j <= i || !active[j] {
					continue
				}
				if v < best {
					best = v
					a, b = i, j
				}
			}
		}
		if a < 0 {
			break
		}

		newID := n + step
		newSize := size[a] + size[b]
		active[a] = false
		active[b] = false
		active[newID] = true
		size[newID] = newSize

		// Average-linkage update against every still-active cluster.
		d[newID] = make(map[int]float64)
		for i := range active {
			if !active[i] || i == newID {
				continue
			}
			da := d[a][i]
			db := d[b][i]
			merged := (da*float64(size[a]) + db*float64(size[b])) / float64(newSize)
			d[newID][i] = merged
			d[i][newID] = merged
		}
		// Drop entries for the merged-away clusters.
		delete(d, a)
		delete(d, b)
		for _, m := range d {
			delete(m, a)
			delete(m, b)
		}

		merges = append(merges, merge{a: a, b: b, dist: best})
	}
	return merges
}

// chooseK picks a cluster count using the largest jump in merge distance.
// The k chosen is clamped to [2, min(maxK, n-1)].
func chooseK(merges []merge, maxK, n int) int {
	if len(merges) < 2 {
		return 1
	}
	upper := maxK
	if upper > n-1 {
		upper = n - 1
	}
	if upper < 2 {
		return 2
	}

	bestK := 2
	bestGap := -1.0
	for i := 1; i < len(merges); i++ {
		k := len(merges) - i + 1
		if k < 2 || k > upper {
			continue
		}
		gap := merges[i].dist - merges[i-1].dist
		if gap > bestGap {
			bestGap = gap
			bestK = k
		}
	}
	return bestK
}

// cutDendrogram returns group assignments after collapsing the dendrogram to
// exactly k surviving clusters. The result is a per-original-point group index
// in [0, k).
func cutDendrogram(merges []merge, n, k int) []int {
	if k <= 1 || len(merges) == 0 {
		out := make([]int, n)
		return out
	}
	// Replay merges only up to the point that leaves k clusters standing.
	stop := len(merges) - (k - 1)
	if stop < 0 {
		stop = 0
	}

	parent := make([]int, 2*n-1)
	for i := range parent {
		parent[i] = i
	}
	for i := 0; i < stop; i++ {
		newID := n + i
		parent[merges[i].a] = newID
		parent[merges[i].b] = newID
	}
	// Resolve each original point to its top-most ancestor (which is a
	// surviving cluster).
	roots := make(map[int]int)
	groups := make([]int, n)
	for i := 0; i < n; i++ {
		r := find(parent, i)
		gid, ok := roots[r]
		if !ok {
			gid = len(roots)
			roots[r] = gid
		}
		groups[i] = gid
	}
	return groups
}

// find returns the root ancestor of x in the parent array.
func find(parent []int, x int) int {
	for parent[x] != x {
		x = parent[x]
	}
	return x
}

// mergeSmallCohorts folds groups smaller than minSize into their nearest
// surviving neighbor, measured as the minimum pairwise distance between any
// member of the small group and any member of the candidate group.
func mergeSmallCohorts(groups []int, profiles []ClusterProfile, minSize int) []int {
	if minSize <= 1 {
		return groups
	}
	counts := make(map[int]int)
	for _, g := range groups {
		counts[g]++
	}
	// Repeat until no cohort is below minSize or only one cohort remains.
	for {
		smallest := -1
		smallestSize := minSize
		for g, c := range counts {
			if c < smallestSize {
				smallest = g
				smallestSize = c
			}
		}
		if smallest < 0 || len(counts) <= 1 {
			break
		}
		target := closestGroup(profiles, groups, smallest)
		if target < 0 {
			break
		}
		for i, g := range groups {
			if g == smallest {
				groups[i] = target
			}
		}
		counts[target] += counts[smallest]
		delete(counts, smallest)
	}
	return renumber(groups)
}

// closestGroup returns the group id closest to the small group, by minimum
// pairwise feature distance, ignoring the small group itself.
func closestGroup(profiles []ClusterProfile, groups []int, small int) int {
	best := -1
	bestDist := math.MaxFloat64
	for i, gi := range groups {
		if gi != small {
			continue
		}
		for j, gj := range groups {
			if gj == small {
				continue
			}
			d := euclidean(profiles[i].Features, profiles[j].Features)
			if d < bestDist {
				bestDist = d
				best = gj
			}
		}
	}
	return best
}

// renumber compacts group ids to a dense [0, K) range so downstream callers
// can use them as slice indices.
func renumber(groups []int) []int {
	remap := make(map[int]int)
	out := make([]int, len(groups))
	for i, g := range groups {
		id, ok := remap[g]
		if !ok {
			id = len(remap)
			remap[g] = id
		}
		out[i] = id
	}
	return out
}
