package imageaudit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// digest is a syntactically valid 64-character sha256 hex string for building
// image references in tests.
var digest = "sha256:" + strings.Repeat("a", 64)

// container builds a named container running the given image.
func container(name, image string) corev1.Container {
	return corev1.Container{Name: name, Image: image}
}

// pod builds a pod with the supplied init and main containers.
func pod(ns, name string, init, main []corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{InitContainers: init, Containers: main},
	}
}

// serviceAccount builds a ServiceAccount with the given imagePullSecrets.
func serviceAccount(ns, name string, secrets ...string) *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	for _, s := range secrets {
		sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: s})
	}
	return sa
}

// dockerSecret builds a Secret carrying a docker config under the given key.
func dockerSecret(ns, name, key, config string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string][]byte{key: []byte(config)},
	}
}

// TestIsLatestOrNoTag checks tag and digest classification, including registry
// ports that must not be mistaken for tags.
func TestIsLatestOrNoTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Image      string
		WantLatest bool
	}{{ // Test 0: Bare name has no tag.
		Image: "nginx", WantLatest: true,
	}, { // Test 1: Explicit latest tag.
		Image: "nginx:latest", WantLatest: true,
	}, { // Test 2: Pinned semver tag is acceptable.
		Image: "nginx:1.25.3", WantLatest: false,
	}, { // Test 3: Registry path without a tag.
		Image: "gcr.io/proj/app", WantLatest: true,
	}, { // Test 4: Registry path with a tag.
		Image: "gcr.io/proj/app:v1", WantLatest: false,
	}, { // Test 5: Digest without a tag still counts as untagged.
		Image: "nginx@" + digest, WantLatest: true,
	}, { // Test 6: Tag plus digest is treated as tagged.
		Image: "nginx:1.2@" + digest, WantLatest: false,
	}, { // Test 7: Registry port is not mistaken for a tag.
		Image: "localhost:5000/app", WantLatest: true,
	}, { // Test 8: Registry port with a real tag.
		Image: "localhost:5000/app:v2", WantLatest: false,
	}, { // Test 9: Registry port with a latest tag.
		Image: "localhost:5000/app:latest", WantLatest: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := isLatestOrNoTag(test.Image)
			if diff := cmp.Diff(test.WantLatest, got); diff != "" {
				t.Errorf("classification mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPullSecretNames checks extraction of secret names from pull-secret refs.
func TestPullSecretNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Refs      []corev1.LocalObjectReference
		WantNames []string
	}{{ // Test 0: Names extracted in order.
		Refs:      []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "other"}},
		WantNames: []string{"regcred", "other"},
	}, { // Test 1: No references yields empty slice.
		Refs: nil, WantNames: []string{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := pullSecretNames(test.Refs)
			if diff := cmp.Diff(test.WantNames, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("names mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDedupe checks duplicate removal with input order preserved.
func TestDedupe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In      []string
		WantOut []string
	}{{ // Test 0: Duplicates removed, first occurrence order kept.
		In: []string{"a", "b", "a", "c", "b"}, WantOut: []string{"a", "b", "c"},
	}, { // Test 1: Empty input yields empty slice.
		In: nil, WantOut: []string{},
	}, { // Test 2: All-unique input preserved.
		In: []string{"x", "y", "z"}, WantOut: []string{"x", "y", "z"},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := dedupe(test.In)
			if diff := cmp.Diff(test.WantOut, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("dedupe mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNormalizeServer checks scheme and trailing-path stripping of docker
// config server keys.
func TestNormalizeServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In       string
		WantHost string
	}{{ // Test 0: Docker index URL normalizes to its host.
		In: "https://index.docker.io/v1/", WantHost: "index.docker.io",
	}, { // Test 1: HTTP scheme and trailing slash stripped.
		In: "http://gcr.io/", WantHost: "gcr.io",
	}, { // Test 2: Bare host is unchanged.
		In: "quay.io", WantHost: "quay.io",
	}, { // Test 3: Trailing slash stripped.
		In: "registry.example.com/", WantHost: "registry.example.com",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := normalizeServer(test.In)
			if diff := cmp.Diff(test.WantHost, got); diff != "" {
				t.Errorf("host mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestToAuthConfig checks conversion of a docker auth entry, including the
// base64 auth field taking precedence and malformed values being ignored.
func TestToAuthConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Entry    dockerAuthEntry
		WantAuth authn.AuthConfig
	}{{ // Test 0: Username and password pass through.
		Entry:    dockerAuthEntry{Username: "user", Password: "pass"},
		WantAuth: authn.AuthConfig{Username: "user", Password: "pass"},
	}, { // Test 1: Base64 auth field decodes into user and password.
		Entry:    dockerAuthEntry{Auth: base64.StdEncoding.EncodeToString([]byte("bob:secret"))},
		WantAuth: authn.AuthConfig{Username: "bob", Password: "secret"},
	}, { // Test 2: Auth field overrides username and password.
		Entry: dockerAuthEntry{
			Username: "ignored", Password: "ignored",
			Auth: base64.StdEncoding.EncodeToString([]byte("bob:secret")),
		},
		WantAuth: authn.AuthConfig{Username: "bob", Password: "secret"},
	}, { // Test 3: Identity token passes through.
		Entry:    dockerAuthEntry{IdentityToken: "tok"},
		WantAuth: authn.AuthConfig{IdentityToken: "tok"},
	}, { // Test 4: Invalid base64 auth leaves user and password intact.
		Entry:    dockerAuthEntry{Username: "user", Password: "pass", Auth: "!!!not-base64!!!"},
		WantAuth: authn.AuthConfig{Username: "user", Password: "pass"},
	}, { // Test 5: Auth without a colon is ignored.
		Entry: dockerAuthEntry{
			Username: "user", Password: "pass",
			Auth: base64.StdEncoding.EncodeToString([]byte("nocolon")),
		},
		WantAuth: authn.AuthConfig{Username: "user", Password: "pass"},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := test.Entry.toAuthConfig()
			if diff := cmp.Diff(test.WantAuth, got); diff != "" {
				t.Errorf("auth mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeDockerConfig checks parsing of dockerconfigjson secrets, the
// config.json fallback key, and malformed or empty inputs.
func TestDecodeDockerConfig(t *testing.T) {
	t.Parallel()

	twoServers := `{"auths":{"gcr.io":{"username":"u","password":"p"},"quay.io":{"auth":"YTpi"}}}`
	oneServer := `{"auths":{"gcr.io":{"username":"u","password":"p"}}}`

	tests := []struct {
		Secret      *corev1.Secret
		WantEntries []authEntry
	}{{ // Test 0: Two servers decoded from dockerconfigjson.
		Secret: dockerSecret("ns", "s", ".dockerconfigjson", twoServers),
		WantEntries: []authEntry{
			{Server: "gcr.io", Auth: authn.AuthConfig{Username: "u", Password: "p"}},
			{Server: "quay.io", Auth: authn.AuthConfig{Username: "a", Password: "b"}},
		},
	}, { // Test 1: config.json fallback key is honored.
		Secret: dockerSecret("ns", "s", "config.json", oneServer),
		WantEntries: []authEntry{
			{Server: "gcr.io", Auth: authn.AuthConfig{Username: "u", Password: "p"}},
		},
	}, { // Test 2: Empty payload yields no entries.
		Secret:      dockerSecret("ns", "s", ".dockerconfigjson", ""),
		WantEntries: nil,
	}, { // Test 3: Invalid JSON yields no entries.
		Secret:      dockerSecret("ns", "s", ".dockerconfigjson", "{not json"),
		WantEntries: nil,
	}, { // Test 4: Missing docker config keys yield no entries.
		Secret:      dockerSecret("ns", "s", "other", "data"),
		WantEntries: nil,
	}}

	sortServers := cmpopts.SortSlices(func(a, b authEntry) bool { return a.Server < b.Server })

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := decodeDockerConfig(test.Secret)
			if diff := cmp.Diff(test.WantEntries, got, sortServers, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestStaticKeychainResolve checks server matching, normalization, and the
// anonymous fallback for the static keychain.
func TestStaticKeychainResolve(t *testing.T) {
	t.Parallel()

	keychain := staticKeychain{
		{Server: "gcr.io", Auth: authn.AuthConfig{Username: "guser", Password: "gpass"}},
		{Server: "https://quay.io/", Auth: authn.AuthConfig{Username: "quser", Password: "qpass"}},
	}

	tests := []struct {
		Repo     string
		WantAuth *authn.AuthConfig
	}{{ // Test 0: Exact server match returns its credential.
		Repo: "gcr.io/proj/app", WantAuth: &authn.AuthConfig{Username: "guser", Password: "gpass"},
	}, { // Test 1: Server needing normalization still matches.
		Repo: "quay.io/org/app", WantAuth: &authn.AuthConfig{Username: "quser", Password: "qpass"},
	}, { // Test 2: Unmatched registry falls back to anonymous.
		Repo: "registry.example.com/app", WantAuth: &authn.AuthConfig{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			target, err := name.NewRepository(test.Repo)
			if err != nil {
				t.Fatalf("parse repository: %v", err)
			}
			authr, err := keychain.Resolve(target)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got, err := authr.Authorization()
			if err != nil {
				t.Fatalf("authorization: %v", err)
			}
			if diff := cmp.Diff(test.WantAuth, got); diff != "" {
				t.Errorf("auth mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProbeCache checks fresh, missing, stale, and default-TTL behavior of the
// probe result cache.
func TestProbeCache(t *testing.T) {
	t.Parallel()

	now := time.Now()
	fresh := ProbeResult{Image: "img", CreatedAt: now}

	tests := []struct {
		Setup   func() *probeCache
		Key     string
		WantRes *ProbeResult
	}{{ // Test 0: Fresh entry is returned.
		Setup: func() *probeCache {
			c := newProbeCache(time.Minute)
			c.put("img", fresh)
			return c
		},
		Key: "img", WantRes: &fresh,
	}, { // Test 1: Missing key returns nil.
		Setup: func() *probeCache { return newProbeCache(time.Minute) },
		Key:   "img", WantRes: nil,
	}, { // Test 2: Stale entry returns nil.
		Setup: func() *probeCache {
			c := newProbeCache(time.Minute)
			c.entries["img"] = cacheEntry{result: fresh, at: now.Add(-time.Hour)}
			return c
		},
		Key: "img", WantRes: nil,
	}, { // Test 3: Non-positive TTL defaults to a usable window.
		Setup: func() *probeCache {
			c := newProbeCache(0)
			c.put("img", fresh)
			return c
		},
		Key: "img", WantRes: &fresh,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := test.Setup().get(test.Key)
			if diff := cmp.Diff(test.WantRes, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestGetCacheOpts checks the cache-read hint passed to per-secret Gets.
func TestGetCacheOpts(t *testing.T) {
	t.Parallel()

	want := metav1.GetOptions{ResourceVersion: "0"}
	if diff := cmp.Diff(want, getCacheOpts()); diff != "" {
		t.Errorf("options mismatch (-want +got):\n%s", diff)
	}
}

// TestCollectSecretNames checks that pod pull secrets and the service account's
// pull secrets are merged and deduplicated, with the default account name used
// when the pod does not set one.
func TestCollectSecretNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Ref       podRef
		SAs       []*corev1.ServiceAccount
		WantNames []string
	}{{ // Test 0: Pod and default account secrets merge and dedupe.
		Ref:       podRef{Namespace: "ns1", PullSecrets: []string{"a", "b"}},
		SAs:       []*corev1.ServiceAccount{serviceAccount("ns1", "default", "b", "c")},
		WantNames: []string{"a", "b", "c"},
	}, { // Test 1: A named service account is consulted.
		Ref:       podRef{Namespace: "ns1", ServiceAccount: "custom"},
		SAs:       []*corev1.ServiceAccount{serviceAccount("ns1", "custom", "x")},
		WantNames: []string{"x"},
	}, { // Test 2: Missing account leaves only pod secrets.
		Ref:       podRef{Namespace: "ns1", PullSecrets: []string{"only"}},
		WantNames: []string{"only"},
	}, { // Test 3: No secrets anywhere yields empty slice.
		Ref:       podRef{Namespace: "ns1"},
		WantNames: []string{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var objects []runtime.Object
			for _, sa := range test.SAs {
				objects = append(objects, sa)
			}
			cs := fakeclientset.NewSimpleClientset(objects...)
			client := kube.NewTestClientWithClientset("test", cs)
			got := collectSecretNames(context.Background(), client, test.Ref)
			if diff := cmp.Diff(test.WantNames, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("names mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestBuildKeychain checks that no credentials yield the default keychain while
// a valid pull secret yields a static keychain that resolves the server.
func TestBuildKeychain(t *testing.T) {
	t.Parallel()

	regcred := dockerSecret("ns1", "regcred", ".dockerconfigjson",
		`{"auths":{"gcr.io":{"username":"u","password":"p"}}}`)

	tests := []struct {
		Ref         podRef
		Secrets     []*corev1.Secret
		WantStatic  bool
		ResolveRepo string
		WantAuth    *authn.AuthConfig
	}{{ // Test 0: No credentials fall back to the default keychain.
		Ref:        podRef{Namespace: "ns1"},
		WantStatic: false,
	}, { // Test 1: A valid pull secret builds a resolving static keychain.
		Ref:         podRef{Namespace: "ns1", PullSecrets: []string{"regcred"}},
		Secrets:     []*corev1.Secret{regcred},
		WantStatic:  true,
		ResolveRepo: "gcr.io/proj/app",
		WantAuth:    &authn.AuthConfig{Username: "u", Password: "p"},
	}, { // Test 2: A referenced but missing secret is skipped.
		Ref:        podRef{Namespace: "ns1", PullSecrets: []string{"missing"}},
		WantStatic: false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var objects []runtime.Object
			for _, s := range test.Secrets {
				objects = append(objects, s)
			}
			cs := fakeclientset.NewSimpleClientset(objects...)
			client := kube.NewTestClientWithClientset("test", cs)

			got := buildKeychain(context.Background(), client, test.Ref)
			_, isStatic := got.(staticKeychain)
			if diff := cmp.Diff(test.WantStatic, isStatic); diff != "" {
				t.Errorf("static keychain mismatch (-want +got):\n%s", diff)
			}
			if !test.WantStatic {
				if got != authn.DefaultKeychain {
					t.Errorf("expected default keychain, got %T", got)
				}
				return
			}
			target, err := name.NewRepository(test.ResolveRepo)
			if err != nil {
				t.Fatalf("parse repository: %v", err)
			}
			authr, err := got.Resolve(target)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			auth, err := authr.Authorization()
			if err != nil {
				t.Fatalf("authorization: %v", err)
			}
			if diff := cmp.Diff(test.WantAuth, auth); diff != "" {
				t.Errorf("auth mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProbeImagesEmpty checks that probing an empty image set does no work.
func TestProbeImagesEmpty(t *testing.T) {
	t.Parallel()

	client := kube.NewTestClient("test", nil)

	tests := []struct {
		ByImage map[string]podRef
	}{{ // Test 0: Nil map returns no results.
		ByImage: nil,
	}, { // Test 1: Empty map returns no results.
		ByImage: map[string]podRef{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := probeImages(context.Background(), client, test.ByImage)
			if got != nil {
				t.Errorf("expected nil results, got %v", got)
			}
		})
	}
}

// TestProbeOneInvalidReference checks that an unparseable image reference is
// reported as an error without any registry contact.
func TestProbeOneInvalidReference(t *testing.T) {
	t.Parallel()

	client := kube.NewTestClient("test", nil)
	got := probeOne(context.Background(), client, "FOO BAR", podRef{})
	if got.Err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if diff := cmp.Diff("FOO BAR", got.Image); diff != "" {
		t.Errorf("image mismatch (-want +got):\n%s", diff)
	}
	if !got.CreatedAt.IsZero() {
		t.Errorf("expected zero creation time, got %v", got.CreatedAt)
	}
}

// TestScanWithProbing checks that Scan folds probe metrics into its result when
// probing is enabled. It toggles the global switch and seeds the global cache
// so no registry is contacted, so it is not parallel.
func TestScanWithProbing(t *testing.T) {
	original := ProbeRegistriesEnabled()
	SetProbeRegistries(true)
	t.Cleanup(func() { SetProbeRegistries(original) })

	img := "gcr.io/proj/app:v1@" + digest
	globalCache.put(img, ProbeResult{Image: img, CreatedAt: time.Now().Add(-30 * 24 * time.Hour)})
	t.Cleanup(func() {
		globalCache.mu.Lock()
		defer globalCache.mu.Unlock()
		delete(globalCache.entries, img)
	})

	cs := fakeclientset.NewSimpleClientset(
		pod("ns", "p", nil, []corev1.Container{container("c0", img)}),
	)
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}
	if diff := cmp.Diff(1, data.ImagesProbed); diff != "" {
		t.Errorf("images probed mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(0, data.ImagesFailed); diff != "" {
		t.Errorf("images failed mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(30, data.OldestImageAgeDays); diff != "" {
		t.Errorf("oldest age mismatch (-want +got):\n%s", diff)
	}
}

// TestFillProbeMetrics checks age aggregation over probe results. It seeds the
// package-global probe cache so probeImages returns deterministic results
// without a registry round-trip, so it is not parallel.
func TestFillProbeMetrics(t *testing.T) {
	client := kube.NewTestClient("test", nil)
	now := time.Now()
	globalCache.put("fs-old", ProbeResult{Image: "fs-old", CreatedAt: now.Add(-100 * 24 * time.Hour)})
	globalCache.put("fs-young", ProbeResult{Image: "fs-young", CreatedAt: now.Add(-50 * 24 * time.Hour)})
	globalCache.put("fs-broken", ProbeResult{Image: "fs-broken", Err: errors.New("boom")})
	t.Cleanup(func() {
		globalCache.mu.Lock()
		defer globalCache.mu.Unlock()
		delete(globalCache.entries, "fs-old")
		delete(globalCache.entries, "fs-young")
		delete(globalCache.entries, "fs-broken")
	})

	byImage := map[string]podRef{"fs-old": {}, "fs-young": {}, "fs-broken": {}}
	var data Data
	fillProbeMetrics(context.Background(), client, byImage, &data)

	if diff := cmp.Diff(2, data.ImagesProbed); diff != "" {
		t.Errorf("images probed mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.ImagesFailed); diff != "" {
		t.Errorf("images failed mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(100, data.OldestImageAgeDays); diff != "" {
		t.Errorf("oldest age mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(75, data.AvgImageAgeDays); diff != "" {
		t.Errorf("average age mismatch (-want +got):\n%s", diff)
	}
}

// TestProbeRegistriesToggle checks the package-global probe toggle. It mutates
// shared state the scanner reads, so it restores the original value and is not
// parallel to avoid overlapping the parallel Scan tests.
func TestProbeRegistriesToggle(t *testing.T) {
	original := ProbeRegistriesEnabled()
	t.Cleanup(func() { SetProbeRegistries(original) })

	if ProbeRegistriesEnabled() {
		t.Fatalf("probe registries should default to off")
	}
	SetProbeRegistries(true)
	if !ProbeRegistriesEnabled() {
		t.Errorf("expected probing enabled after set true")
	}
	SetProbeRegistries(false)
	if ProbeRegistriesEnabled() {
		t.Errorf("expected probing disabled after set false")
	}
}

// TestScan drives the full image audit over the typed fake with registry
// probing off, covering risk classification, init-container counting, the
// empty cluster, and a pod list error.
func TestScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Pods     []*corev1.Pod
		ListErr  bool
		WantData Data
	}{{ // Test 0: Risks classified and sorted by count, init container counted.
		Pods: []*corev1.Pod{
			pod("ns1", "p1",
				[]corev1.Container{container("i0", "alpine:3.19@"+digest)},
				[]corev1.Container{container("c1", "nginx:latest")}),
			pod("ns2", "p2", nil, []corev1.Container{container("c2", "myrepo:1.0")}),
		},
		WantData: Data{
			TotalContainers: 3, LatestTag: 1, NoDigest: 2, UniqueImages: 3,
			ImageRisks: []ImageRisk{
				{
					Namespace: "ns1", Pod: "p1", Container: "c1", Image: "nginx:latest",
					Risks: []string{"latest-or-no-tag", "no-digest-pin"},
				},
				{
					Namespace: "ns2", Pod: "p2", Container: "c2", Image: "myrepo:1.0",
					Risks: []string{"no-digest-pin"},
				},
			},
		},
	}, { // Test 1: An empty cluster reports zeroes.
		Pods:     nil,
		WantData: Data{},
	}, { // Test 2: A pod list error is wrapped as a scan failure.
		Pods:    nil,
		ListErr: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var objects []runtime.Object
			for _, p := range test.Pods {
				objects = append(objects, p)
			}
			cs := fakeclientset.NewSimpleClientset(objects...)
			if test.ListErr {
				cs.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("boom")
				})
			}
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if test.ListErr {
				if !errors.Is(err, scanner.ErrScan) {
					t.Fatalf("expected ErrScan, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(Name, result.Scanner); diff != "" {
				t.Errorf("scanner name mismatch (-want +got):\n%s", diff)
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

// TestScanTruncatesImageRisks checks that the reported risk list is capped at
// fifty while the aggregate counts still reflect every container.
func TestScanTruncatesImageRisks(t *testing.T) {
	t.Parallel()

	var objects []runtime.Object
	for i := range 60 {
		objects = append(objects, pod("ns", fmt.Sprintf("p%d", i), nil,
			[]corev1.Container{container("c0", fmt.Sprintf("img-%d", i))}))
	}
	cs := fakeclientset.NewSimpleClientset(objects...)
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}

	if diff := cmp.Diff(60, data.TotalContainers); diff != "" {
		t.Errorf("total containers mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(60, data.UniqueImages); diff != "" {
		t.Errorf("unique images mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(60, data.LatestTag); diff != "" {
		t.Errorf("latest tag mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(60, data.NoDigest); diff != "" {
		t.Errorf("no digest mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(50, len(data.ImageRisks)); diff != "" {
		t.Errorf("image risks length mismatch (-want +got):\n%s", diff)
	}
}
