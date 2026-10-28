//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	// fleetPrefix starts the name of every cluster a fleet owns, so leftovers from a run
	// that died before cleanup can be found and deleted.
	fleetPrefix = "fs-fleet-"
	// fleetCreateBound caps how many kind clusters are created at once.
	fleetCreateBound = 3
	// imageDefault is the node image kind v0.33 uses when none is given.
	imageDefault = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
	// imageOld is an older node image, so a fleet can carry real version skew.
	imageOld = "kindest/node:v1.30.8"
	// kindLogsEnv names a directory that receives each cluster's kind logs when a test fails.
	kindLogsEnv = "FLEET_KIND_LOGS"
)

var (
	// runStamp identifies this test process in cluster names. It is base36 seconds since
	// the epoch, so a smaller stamp is an older run.
	runStamp = strconv.FormatInt(time.Now().Unix(), 36) //nolint:gochecknoglobals // Set once per process.
	// fleetSeq tells apart fleets created by one process.
	fleetSeq atomic.Int64 //nolint:gochecknoglobals // Process-wide counter.
	// binOnce builds the fleetsweeper binary once per test binary.
	binOnce sync.Once //nolint:gochecknoglobals // Process-wide build.
	// binPath is the built binary, set by binOnce.
	binPath string //nolint:gochecknoglobals // Set once by binOnce.
	// binErr is the build error, set by binOnce.
	binErr error //nolint:gochecknoglobals // Set once by binOnce.
	// binDir holds the built binary and is removed by TestMain.
	binDir string //nolint:gochecknoglobals // Set once by binOnce.
)

// TestMain runs the tests and removes the shared binary directory afterward.
func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// fleet is a set of kind clusters created for one test and deleted on its cleanup.
type fleet struct {
	// t is the owning test.
	t *testing.T
	// names are the kind cluster names, in creation order.
	names []string
	// kubeconfig is the merged kubeconfig holding every cluster's context.
	kubeconfig string
	// mu guards clientsets.
	mu sync.Mutex
	// clientsets caches one clientset per cluster index.
	clientsets map[int]kubernetes.Interface
}

// newFleet creates one kind cluster per image, at most fleetCreateBound at a time, merges
// their kubeconfigs into one file, and registers cleanup. An empty image means imageDefault.
// It deletes leftover fleet clusters from older runs before creating any.
func newFleet(t *testing.T, images ...string) *fleet {
	t.Helper()
	return newFleetBounded(t, fleetCreateBound, images...)
}

// newFleetBounded is newFleet with an explicit creation bound.
func newFleetBounded(t *testing.T, bound int, images ...string) *fleet {
	t.Helper()
	requireKind(t)
	requireDocker(t)
	deleteLeftoverFleets(t)

	seq := fleetSeq.Add(1)
	dir := t.TempDir()
	f := &fleet{
		t:          t,
		names:      make([]string, len(images)),
		kubeconfig: filepath.Join(dir, "kubeconfig"),
		clientsets: map[int]kubernetes.Interface{},
	}
	for i := range images {
		f.names[i] = fmt.Sprintf("%s%s-%d-%d", fleetPrefix, runStamp, seq, i+1)
	}
	t.Cleanup(f.delete)

	ctx := t.Context()
	sem := make(chan struct{}, bound)
	var wg sync.WaitGroup
	errs := make([]error, len(images))
	paths := make([]string, len(images))
	for i, image := range images {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			errs[i] = ctx.Err()
			continue
		}
		wg.Add(1)
		go func(i int, image string) {
			defer wg.Done()
			defer func() { <-sem }()
			if image == "" {
				image = imageDefault
			}
			paths[i] = filepath.Join(dir, fmt.Sprintf("kubeconfig-%d", i+1))
			errs[i] = createKindCluster(ctx, f.names[i], image, paths[i])
		}(i, image)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("create fleet: %v", err)
	}
	if err := mergeKubeconfigs(f.kubeconfig, paths); err != nil {
		t.Fatalf("merge kubeconfigs: %v", err)
	}
	t.Logf("fleet up: %s", strings.Join(f.names, ", "))
	return f
}

// createKindCluster creates one single-node kind cluster from the shared resource-light
// config and writes its kubeconfig to kubeconfigPath.
func createKindCluster(ctx context.Context, name, image, kubeconfigPath string) error {
	cmd := exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", name,
		"--image", image,
		"--config", filepath.Join(repoRoot(), "internal", "integration", "testdata", "kind-node.yaml"),
		"--kubeconfig", kubeconfigPath,
		"--wait", "180s",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kind create %s: %w: %s", name, err, stderr.String())
	}
	return nil
}

// mergeKubeconfigs writes one kubeconfig holding every context from paths.
func mergeKubeconfigs(out string, paths []string) error {
	merged := clientcmdapi.NewConfig()
	for _, p := range paths {
		cfg, err := clientcmd.LoadFromFile(p)
		if err != nil {
			return fmt.Errorf("load %s: %w", p, err)
		}
		for k, v := range cfg.Clusters {
			merged.Clusters[k] = v
		}
		for k, v := range cfg.AuthInfos {
			merged.AuthInfos[k] = v
		}
		for k, v := range cfg.Contexts {
			merged.Contexts[k] = v
		}
		if merged.CurrentContext == "" {
			merged.CurrentContext = cfg.CurrentContext
		}
	}
	return clientcmd.WriteToFile(*merged, out)
}

// delete removes every cluster the fleet owns. When the test failed and FLEET_KIND_LOGS names a
// directory, it first exports each cluster's kind logs there, so CI can upload them.
func (f *fleet) delete() {
	dir := os.Getenv(kindLogsEnv)
	for _, name := range f.names {
		if dir != "" && f.t.Failed() {
			exportKindLogs(f.t, name, filepath.Join(dir, name))
		}
		deleteCluster(f.t, name)
	}
}

// exportKindLogs writes the kind logs of cluster name to dir. A failure is logged, not fatal,
// because the test has already failed and the cluster must still be deleted.
func exportKindLogs(t *testing.T, name, dir string) {
	t.Helper()
	out, err := exec.Command("kind", "export", "logs", dir, "--name", name).CombinedOutput()
	if err != nil {
		t.Logf("warning: export kind logs for %s: %v\n%s", name, err, out)
		return
	}
	t.Logf("kind logs for %s written to %s", name, dir)
}

// KubeconfigPath returns the merged kubeconfig for every cluster in the fleet.
func (f *fleet) KubeconfigPath() string {
	return f.kubeconfig
}

// Contexts returns the kubeconfig context of every cluster, in creation order.
func (f *fleet) Contexts() []string {
	out := make([]string, len(f.names))
	for i, n := range f.names {
		out[i] = kindContext(n)
	}
	return out
}

// Clientset returns a clientset for cluster i, built once and cached.
func (f *fleet) Clientset(i int) kubernetes.Interface {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if cs, ok := f.clientsets[i]; ok {
		return cs
	}
	cs := clientsetForContext(f.t, f.kubeconfig, kindContext(f.names[i]))
	f.clientsets[i] = cs
	return cs
}

// deleteLeftoverFleets deletes fleet clusters left by older runs that died before cleanup.
// A cluster belongs to an older run when its stamp sorts before this process's stamp.
func deleteLeftoverFleets(t *testing.T) {
	t.Helper()
	out, err := exec.Command("kind", "get", "clusters").Output()
	if err != nil {
		t.Logf("warning: list kind clusters: %v", err)
		return
	}
	for _, name := range strings.Fields(string(out)) {
		if leftoverFleet(name, runStamp) {
			t.Logf("deleting leftover fleet cluster %s", name)
			deleteCluster(t, name)
		}
	}
}

// leftoverFleet reports whether name is a fleet cluster from a run older than stamp.
func leftoverFleet(name, stamp string) bool {
	rest, ok := strings.CutPrefix(name, fleetPrefix)
	if !ok {
		return false
	}
	theirs, _, _ := strings.Cut(rest, "-")
	a, errA := strconv.ParseInt(theirs, 36, 64)
	b, errB := strconv.ParseInt(stamp, 36, 64)
	return errA == nil && errB == nil && a < b
}

// fleetBinary builds the fleetsweeper binary once per test binary and returns its path.
func fleetBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "fleetsweeper-bin-")
		if binErr != nil {
			return
		}
		binPath = filepath.Join(binDir, "fleetsweeper")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Dir = repoRoot()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			binErr = fmt.Errorf("go build: %w: %s", err, stderr.String())
		}
	})
	if binErr != nil {
		t.Fatalf("build fleetsweeper: %v", binErr)
	}
	return binPath
}

// cliResult is the outcome of one fleetsweeper invocation.
type cliResult struct {
	// Stdout is what the command wrote to stdout.
	Stdout string
	// Stderr is what the command wrote to stderr.
	Stderr string
	// Exit is the process exit code.
	Exit int
}

// runCLI runs the built binary with the fleet's kubeconfig and returns its output and exit
// code. A failure to start the process fails the test; a nonzero exit does not.
func (f *fleet) runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), fleetBinary(t), args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+f.kubeconfig)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := cliResult{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		res.Exit = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("run fleetsweeper %v: %v", args, err)
	}
	return res
}

// TestFleetHarness stands up three clusters, one on the older node image, and checks each
// reports the server version its image carries.
func TestFleetHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	start := time.Now()
	f := newFleet(t, "", "", imageOld)
	t.Logf("three clusters created in %s", time.Since(start).Round(time.Second))

	want := []string{"v1.37", "v1.37", "v1.30"}
	for i := range want {
		v, err := f.Clientset(i).Discovery().ServerVersion()
		if err != nil {
			t.Fatalf("cluster %d server version: %v", i+1, err)
		}
		t.Logf("cluster %d (%s): %s", i+1, f.Contexts()[i], v.GitVersion)
		if !strings.HasPrefix(v.GitVersion, want[i]) {
			t.Errorf("cluster %d: want %s.x, got %s", i+1, want[i], v.GitVersion)
		}
	}
	res := f.runCLI(t, "version")
	if res.Exit != 0 {
		t.Errorf("fleetsweeper version: exit %d, stderr %s", res.Exit, res.Stderr)
	}
}

// TestLeftoverFleet checks which cluster names count as leftovers from an older run.
func TestLeftoverFleet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Stamp      string
		WantResult bool
	}{{ // Test 0: Older stamp is a leftover.
		Name: "fs-fleet-a-1-1", Stamp: "b", WantResult: true,
	}, { // Test 1: Same stamp belongs to this run.
		Name: "fs-fleet-b-1-1", Stamp: "b", WantResult: false,
	}, { // Test 2: Newer stamp belongs to a later run.
		Name: "fs-fleet-c-1-1", Stamp: "b", WantResult: false,
	}, { // Test 3: Other prefixes are never touched.
		Name: "fleetsweeper-alpha", Stamp: "b", WantResult: false,
	}, { // Test 4: Unparseable stamp is never touched.
		Name: "fs-fleet-!!-1-1", Stamp: "b", WantResult: false,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := leftoverFleet(test.Name, test.Stamp); got != test.WantResult {
				t.Errorf("leftoverFleet(%q, %q) = %v, want %v", test.Name, test.Stamp, got, test.WantResult)
			}
		})
	}
}

// clientsetForContext creates a Kubernetes clientset for a specific kubeconfig context.
func clientsetForContext(t *testing.T, kubeconfigPath, contextName string) kubernetes.Interface {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	).ClientConfig()
	if err != nil {
		t.Fatalf("build config for %s: %v", contextName, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("create clientset for %s: %v", contextName, err)
	}
	return cs
}

// kindContext returns the kubeconfig context name for a kind cluster.
func kindContext(clusterName string) string {
	return fmt.Sprintf("kind-%s", clusterName)
}

// createCluster creates a kind cluster and merges its kubeconfig into the given path.
func createCluster(t *testing.T, name, kubeconfigPath string) {
	t.Helper()
	cmd := exec.Command("kind", "create", "cluster",
		"--name", name,
		"--kubeconfig", kubeconfigPath,
		"--wait", "120s",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("create kind cluster %s: %v\n%s", name, err, stderr.String())
	}
	t.Logf("created kind cluster %s", name)
}

// deleteCluster removes a kind cluster.
func deleteCluster(t *testing.T, name string) {
	t.Helper()
	cmd := exec.Command("kind", "delete", "cluster", "--name", name)
	if err := cmd.Run(); err != nil {
		t.Logf("warning: failed to delete kind cluster %s: %v", name, err)
	}
}

// requireKind skips the test if kind is not installed.
func requireKind(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind not found in PATH; install with: brew install kind")
	}
}

// requireDocker skips the test if Docker is not running.
func requireDocker(t *testing.T) {
	t.Helper()
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		t.Skip("docker not running; start Docker Desktop to run integration tests")
	}
}
