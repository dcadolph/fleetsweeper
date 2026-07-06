package imageaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// authEntry pairs an authn.AuthConfig with the server hostname it applies to.
// authn.AuthConfig itself does not carry the server address; we track it
// alongside so the keychain can match a registry lookup to its credential.
type authEntry struct {
	// Server is the registry hostname (normalized, no scheme).
	Server string
	// Auth is the credential for that server.
	Auth authn.AuthConfig
}

// getCacheOpts returns a ListOptions/GetOptions value that hints to the
// apiserver that a slightly stale cache read is acceptable. Reduces load on
// large clusters; the consistency cost is negligible for pull-secret reads.
func getCacheOpts() metav1.GetOptions {
	return metav1.GetOptions{ResourceVersion: "0"}
}

// ProbeResult captures the outcome of resolving one image manifest. Used
// internally; the aggregated counts surface on Data.
type ProbeResult struct {
	// Image is the resolved reference (canonical form).
	Image string
	// CreatedAt is the manifest's reported creation time. Zero when the
	// registry did not return a Created field on the config blob.
	CreatedAt time.Time
	// Err is the error encountered, if any.
	Err error
}

// probeCache memoises ProbeResult by image reference so multiple pods
// referencing the same image only round-trip the registry once per scan
// across clusters within the cache lifetime.
type probeCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

// cacheEntry is one cached ProbeResult plus its capture time.
type cacheEntry struct {
	result ProbeResult
	at     time.Time
}

// newProbeCache constructs an empty cache with the supplied TTL.
func newProbeCache(ttl time.Duration) *probeCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &probeCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// get returns a cached entry when fresh, otherwise nil.
func (c *probeCache) get(key string) *ProbeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Since(e.at) > c.ttl {
		return nil
	}
	r := e.result
	return &r
}

// put stores a fresh entry.
func (c *probeCache) put(key string, r ProbeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{result: r, at: time.Now()}
}

// globalCache is shared across scans so a 5-minute window of probing
// against the same image landscape costs one round-trip per image.
var globalCache = newProbeCache(5 * time.Minute)

// probeImages resolves manifests for the supplied image references using
// auth derived from the pod imagePullSecrets associated with each image.
// Returns a per-image ProbeResult slice plus aggregate counts.
//
// The function is best-effort: registry errors are recorded on the
// individual result and never fail the surrounding scan.
func probeImages(ctx context.Context, client *kube.Client, byImage map[string]podRef) []ProbeResult {
	if len(byImage) == 0 {
		return nil
	}
	out := make([]ProbeResult, 0, len(byImage))
	for image, ref := range byImage {
		if cached := globalCache.get(image); cached != nil {
			out = append(out, *cached)
			continue
		}
		res := probeOne(ctx, client, image, ref)
		globalCache.put(image, res)
		out = append(out, res)
	}
	return out
}

// podRef remembers one pod that uses a given image, so we can look up
// imagePullSecrets when authenticating to the registry.
type podRef struct {
	// Namespace is the pod's namespace.
	Namespace string
	// ServiceAccount is the pod's serviceAccountName (empty becomes "default").
	ServiceAccount string
	// PullSecrets are the LocalObjectReference names attached to the pod
	// spec.imagePullSecrets.
	PullSecrets []string
}

// probeOne probes a single image and returns the result.
func probeOne(ctx context.Context, client *kube.Client, image string, ref podRef) ProbeResult {
	parsed, err := name.ParseReference(image)
	if err != nil {
		return ProbeResult{Image: image, Err: fmt.Errorf("parse: %w", err)}
	}

	keychain := buildKeychain(ctx, client, ref)
	desc, err := remote.Get(parsed,
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return ProbeResult{Image: image, Err: fmt.Errorf("manifest: %w", err)}
	}

	cfg, err := remote.Image(parsed,
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		// We have the manifest but not the config blob; still useful.
		return ProbeResult{Image: parsed.Name(), Err: fmt.Errorf("image: %w", err)}
	}
	cf, err := cfg.ConfigFile()
	if err != nil {
		return ProbeResult{Image: parsed.Name(), Err: fmt.Errorf("config file: %w", err)}
	}
	created := cf.Created.Time
	_ = desc
	return ProbeResult{Image: parsed.Name(), CreatedAt: created}
}

// buildKeychain assembles a go-containerregistry authn.Keychain from the
// supplied pod's imagePullSecrets plus the namespace's default service
// account. Falls back to authn.DefaultKeychain (which understands
// $DOCKER_CONFIG and the in-cluster $HOME/.docker/config.json) when no
// pod-level secrets are configured.
func buildKeychain(ctx context.Context, client *kube.Client, ref podRef) authn.Keychain {
	var entries []authEntry
	for _, secretName := range collectSecretNames(ctx, client, ref) {
		secret, err := client.Clientset().CoreV1().Secrets(ref.Namespace).Get(ctx, secretName, getCacheOpts())
		if err != nil {
			continue
		}
		entries = append(entries, decodeDockerConfig(secret)...)
	}
	if len(entries) == 0 {
		return authn.DefaultKeychain
	}
	return staticKeychain(entries)
}

// collectSecretNames returns the imagePullSecret names from the pod plus
// the namespace's default service account's imagePullSecrets.
func collectSecretNames(ctx context.Context, client *kube.Client, ref podRef) []string {
	names := make([]string, 0, len(ref.PullSecrets)+1)
	names = append(names, ref.PullSecrets...)
	saName := ref.ServiceAccount
	if saName == "" {
		saName = "default"
	}
	sa, err := client.Clientset().CoreV1().ServiceAccounts(ref.Namespace).Get(ctx, saName, getCacheOpts())
	if err == nil {
		for _, s := range sa.ImagePullSecrets {
			names = append(names, s.Name)
		}
	}
	return dedupe(names)
}

// decodeDockerConfig pulls every server credential pair out of a
// kubernetes.io/dockerconfigjson Secret.
func decodeDockerConfig(secret *corev1.Secret) []authEntry {
	raw, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		raw = secret.Data["config.json"]
	}
	if len(raw) == 0 {
		return nil
	}
	var cfg dockerConfigJSON
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	out := make([]authEntry, 0, len(cfg.Auths))
	for server, entry := range cfg.Auths {
		out = append(out, authEntry{Server: server, Auth: entry.toAuthConfig()})
	}
	return out
}

// dockerConfigJSON is the subset of the Docker config we read.
type dockerConfigJSON struct {
	// Auths is the per-server credential map.
	Auths map[string]dockerAuthEntry `json:"auths"`
}

// dockerAuthEntry is one server's stored credentials.
type dockerAuthEntry struct {
	// Username is the registry user when stored in plaintext.
	Username string `json:"username,omitempty"`
	// Password is the matching password.
	Password string `json:"password,omitempty"`
	// Auth is the optional base64("user:pass") form.
	Auth string `json:"auth,omitempty"`
	// IdentityToken is the optional OAuth token form.
	IdentityToken string `json:"identitytoken,omitempty"`
}

// toAuthConfig converts a Docker config entry into go-containerregistry's
// AuthConfig type. When `auth` is set it takes precedence over user/pass.
func (e dockerAuthEntry) toAuthConfig() authn.AuthConfig {
	ac := authn.AuthConfig{
		Username:      e.Username,
		Password:      e.Password,
		IdentityToken: e.IdentityToken,
	}
	if e.Auth != "" {
		if decoded, err := base64.StdEncoding.DecodeString(e.Auth); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				ac.Username = parts[0]
				ac.Password = parts[1]
			}
		}
	}
	return ac
}

// staticKeychain is an authn.Keychain backed by a fixed authEntry list.
// Registry lookups are matched by server hostname; the first matching
// entry wins.
type staticKeychain []authEntry

// Resolve implements authn.Keychain. It compares the resource's registry
// host against the configured server entries.
func (k staticKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	host := target.RegistryStr()
	for _, entry := range k {
		if normalizeServer(entry.Server) == host {
			return authn.FromConfig(entry.Auth), nil
		}
	}
	return authn.Anonymous, nil
}

// normalizeServer strips scheme and trailing slashes so docker config keys
// like "https://index.docker.io/v1/" resolve to "index.docker.io".
func normalizeServer(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/v1/")
	s = strings.TrimSuffix(s, "/")
	return s
}

// dedupe removes duplicate strings preserving input order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ensureType keeps the v1 import referenced for callers that might later
// build with -trimpath in unusual contexts. The reference is otherwise
// indirect via the remote package.
var _ = v1.Hash{}
