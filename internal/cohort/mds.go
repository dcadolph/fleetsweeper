package cohort

import (
	"math"
	"sort"
)

// Map is a two-dimensional picture of a fleet's cohort feature vectors: where
// each cluster sits, which clusters it is closest to, and an order that keeps
// every cohort contiguous for a seriated matrix.
type Map struct {
	// Points holds one entry per cluster, in profile order.
	Points []MapPoint `json:"points"`
	// LeafOrder lists every cluster with each cohort as one contiguous run.
	// Cohorts appear in the order their first member appears in the
	// dendrogram's leaf order, and members keep that leaf order within a run.
	LeafOrder []string `json:"leaf_order"`
	// Stress is Kruskal's stress-1 of the 2D layout against the feature
	// distances: 0 is a perfect fit, and above about 0.2 the picture is a
	// rough guide.
	Stress float64 `json:"stress"`
}

// MapPoint is one cluster on the cohort map.
type MapPoint struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Cohort is the name of the cohort the cluster belongs to.
	Cohort string `json:"cohort"`
	// X is the first classical MDS coordinate.
	X float64 `json:"x"`
	// Y is the second classical MDS coordinate.
	Y float64 `json:"y"`
	// Peers lists the nearest other clusters by feature distance, closest
	// first.
	Peers []Peer `json:"peers,omitempty"`
}

// Peer is a nearby cluster and its feature distance.
type Peer struct {
	// Cluster is the peer's name.
	Cluster string `json:"cluster"`
	// Distance is the Euclidean distance between the two feature vectors.
	Distance float64 `json:"distance"`
}

// jacobiMaxSweeps bounds the eigenvalue iteration. Cyclic Jacobi converges
// quadratically, so well-conditioned inputs finish in under a dozen sweeps.
const jacobiMaxSweeps = 100

// BuildMap lays profiles out in two dimensions with classical
// multidimensional scaling of their pairwise feature distances, lists up to
// peers nearest neighbors per cluster, and orders clusters for a seriated
// view. cohorts assigns each profile its cohort name; a profile in no cohort
// gets an empty one.
func BuildMap(profiles []ClusterProfile, cohorts []Cohort, peers int) Map {
	n := len(profiles)
	if n == 0 {
		return Map{}
	}
	cohortOf := make(map[string]string, n)
	for _, c := range cohorts {
		for _, name := range c.Clusters {
			cohortOf[name] = c.Name
		}
	}
	dist := pairwiseDistances(profiles)
	coords := classicalMDS(dist)

	m := Map{
		Points:    make([]MapPoint, n),
		LeafOrder: seriate(profiles, dist, cohortOf),
		Stress:    stress(dist, coords),
	}
	for i, p := range profiles {
		m.Points[i] = MapPoint{
			Cluster: p.Name,
			Cohort:  cohortOf[p.Name],
			X:       coords[i][0],
			Y:       coords[i][1],
			Peers:   nearestPeers(profiles, dist, i, peers),
		}
	}
	return m
}

// classicalMDS returns 2D coordinates whose Euclidean distances approximate
// dist. It double-centers the squared distances and scales the two leading
// eigenvectors by the square roots of their eigenvalues. A negative or absent
// eigenvalue yields a zero coordinate. Each axis is signed so its largest
// component is positive, which keeps the layout stable across runs.
func classicalMDS(dist [][]float64) [][2]float64 {
	n := len(dist)
	coords := make([][2]float64, n)
	if n < 2 {
		return coords
	}
	b := doubleCenter(dist)
	vals, vecs := jacobiEigen(b)

	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return vals[order[i]] > vals[order[j]] })

	for axis := 0; axis < 2 && axis < n; axis++ {
		k := order[axis]
		if vals[k] <= 0 {
			continue
		}
		scale := math.Sqrt(vals[k])
		sign := axisSign(vecs, k)
		for i := range n {
			coords[i][axis] = sign * vecs[i][k] * scale
		}
	}
	return coords
}

// doubleCenter returns -1/2 J D² J for the distance matrix dist, where J is
// the centering matrix.
func doubleCenter(dist [][]float64) [][]float64 {
	n := len(dist)
	sq := make([][]float64, n)
	rowMean := make([]float64, n)
	var grand float64
	for i := range n {
		sq[i] = make([]float64, n)
		for j := range n {
			v := dist[i][j] * dist[i][j]
			sq[i][j] = v
			rowMean[i] += v
		}
		grand += rowMean[i]
		rowMean[i] /= float64(n)
	}
	grand /= float64(n * n)
	b := make([][]float64, n)
	for i := range n {
		b[i] = make([]float64, n)
		for j := range n {
			b[i][j] = -0.5 * (sq[i][j] - rowMean[i] - rowMean[j] + grand)
		}
	}
	return b
}

// axisSign returns -1 when the largest-magnitude component of eigenvector k is
// negative, else 1. Ties go to the lowest index.
func axisSign(vecs [][]float64, k int) float64 {
	best, sign := 0.0, 1.0
	for i := range vecs {
		if a := math.Abs(vecs[i][k]); a > best+1e-12 {
			best = a
			sign = math.Copysign(1, vecs[i][k])
		}
	}
	return sign
}

// jacobiEigen returns the eigenvalues of the symmetric matrix a and the
// matching eigenvectors as columns: vecs[i][k] is component i of eigenvector
// k. It uses cyclic Jacobi rotations and does not modify a.
func jacobiEigen(a [][]float64) ([]float64, [][]float64) {
	n := len(a)
	m := make([][]float64, n)
	v := make([][]float64, n)
	var norm float64
	for i := range n {
		m[i] = append([]float64(nil), a[i]...)
		v[i] = make([]float64, n)
		v[i][i] = 1
		for j := range n {
			norm += a[i][j] * a[i][j]
		}
	}
	tol := 1e-24 * math.Max(norm, 1)

	for sweep := 0; sweep < jacobiMaxSweeps; sweep++ {
		var off float64
		for p := range n {
			for q := p + 1; q < n; q++ {
				off += m[p][q] * m[p][q]
			}
		}
		if off <= tol {
			break
		}
		for p := range n {
			for q := p + 1; q < n; q++ {
				apq := m[p][q]
				if apq == 0 {
					continue
				}
				theta := (m[q][q] - m[p][p]) / (2 * apq)
				t := 1 / (math.Abs(theta) + math.Sqrt(theta*theta+1))
				if theta < 0 {
					t = -t
				}
				c := 1 / math.Sqrt(t*t+1)
				s := t * c
				for r := range n {
					if r == p || r == q {
						continue
					}
					arp, arq := m[r][p], m[r][q]
					m[r][p] = c*arp - s*arq
					m[p][r] = m[r][p]
					m[r][q] = c*arq + s*arp
					m[q][r] = m[r][q]
				}
				m[p][p] -= t * apq
				m[q][q] += t * apq
				m[p][q], m[q][p] = 0, 0
				for r := range n {
					vrp, vrq := v[r][p], v[r][q]
					v[r][p] = c*vrp - s*vrq
					v[r][q] = s*vrp + c*vrq
				}
			}
		}
	}
	vals := make([]float64, n)
	for i := range n {
		vals[i] = m[i][i]
	}
	return vals, v
}

// stress returns Kruskal's stress-1 of coords against dist.
func stress(dist [][]float64, coords [][2]float64) float64 {
	var num, den float64
	for i := range dist {
		for j := i + 1; j < len(dist); j++ {
			fit := math.Hypot(coords[i][0]-coords[j][0], coords[i][1]-coords[j][1])
			diff := dist[i][j] - fit
			num += diff * diff
			den += dist[i][j] * dist[i][j]
		}
	}
	if den == 0 {
		return 0
	}
	return math.Sqrt(num / den)
}

// nearestPeers returns up to k profiles closest to profile i, nearest first,
// ties broken by name.
func nearestPeers(profiles []ClusterProfile, dist [][]float64, i, k int) []Peer {
	if k <= 0 {
		return nil
	}
	out := make([]Peer, 0, len(profiles)-1)
	for j, p := range profiles {
		if j == i {
			continue
		}
		out = append(out, Peer{Cluster: p.Name, Distance: dist[i][j]})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Distance != out[b].Distance {
			return out[a].Distance < out[b].Distance
		}
		return out[a].Cluster < out[b].Cluster
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// seriate orders clusters by the average-linkage dendrogram's leaf order, then
// gathers each cohort into one contiguous run placed where its first member
// fell, so a seriated matrix shows cohorts as blocks.
func seriate(profiles []ClusterProfile, dist [][]float64, cohortOf map[string]string) []string {
	n := len(profiles)
	leaves := leafOrder(buildDendrogram(n, dist), n)

	var blocks []string
	members := make(map[string][]string)
	for _, idx := range leaves {
		name := profiles[idx].Name
		c := cohortOf[name]
		if _, seen := members[c]; !seen {
			blocks = append(blocks, c)
		}
		members[c] = append(members[c], name)
	}
	out := make([]string, 0, n)
	for _, c := range blocks {
		out = append(out, members[c]...)
	}
	return out
}

// leafOrder returns the original point indices in the left-to-right order of
// the dendrogram described by merges, where merge s creates cluster n+s from
// its a and b children. Points the last merge does not reach follow in index
// order.
func leafOrder(merges []merge, n int) []int {
	if n == 0 {
		return nil
	}
	if len(merges) == 0 {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	out := make([]int, 0, n)
	stack := []int{n + len(merges) - 1}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if id < n {
			out = append(out, id)
			continue
		}
		m := merges[id-n]
		stack = append(stack, m.b, m.a)
	}
	if len(out) < n {
		seen := make([]bool, n)
		for _, i := range out {
			seen[i] = true
		}
		for i := range n {
			if !seen[i] {
				out = append(out, i)
			}
		}
	}
	return out
}
