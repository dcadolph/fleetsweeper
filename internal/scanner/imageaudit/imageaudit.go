package imageaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// probeRegistries is the package-level toggle for registry probing.
// Operators flip it via SetProbeRegistries from the serve command so the
// scanner stays useful in low-egress environments where the registry
// round-trip is undesirable.
var (
	probeMu        sync.RWMutex
	probeEnabled   bool
	probeTimeoutMS = 5000
)

// SetProbeRegistries toggles the registry-probe path. Off by default.
// Callers set it once at startup from a flag value.
func SetProbeRegistries(enabled bool) {
	probeMu.Lock()
	defer probeMu.Unlock()
	probeEnabled = enabled
}

// ProbeRegistriesEnabled reports the current toggle state.
func ProbeRegistriesEnabled() bool {
	probeMu.RLock()
	defer probeMu.RUnlock()
	return probeEnabled
}

// Name is the registry key for this scanner.
const Name = "image-audit"

// ImageRisk describes a container image with a hygiene concern.
type ImageRisk struct {
	// Namespace is the pod's namespace.
	Namespace string `json:"namespace"`
	// Pod is the pod name.
	Pod string `json:"pod"`
	// Container is the container name.
	Container string `json:"container"`
	// Image is the full image reference.
	Image string `json:"image"`
	// Risks lists the specific concerns.
	Risks []string `json:"risks"`
}

// Data holds image audit results for one cluster.
type Data struct {
	// TotalContainers is the number of containers scanned.
	TotalContainers int `json:"total_containers"`
	// LatestTag is containers using the :latest tag or no tag.
	LatestTag int `json:"latest_tag"`
	// NoDigest is containers without a digest pin (@sha256:...).
	NoDigest int `json:"no_digest"`
	// UniqueImages is the number of distinct image references.
	UniqueImages int `json:"unique_images"`
	// ImageRisks lists containers with image hygiene concerns.
	ImageRisks []ImageRisk `json:"image_risks"`
	// ImagesProbed is the number of unique images successfully resolved
	// against their registry. Zero when --probe-registries is off.
	ImagesProbed int `json:"images_probed"`
	// ImagesFailed is the number of probe attempts that errored.
	ImagesFailed int `json:"images_failed"`
	// OldestImageAgeDays is the age of the oldest successfully-probed image
	// expressed in days since its registry-reported creation time.
	OldestImageAgeDays int `json:"oldest_image_age_days"`
	// AvgImageAgeDays is the mean age across all probed images.
	AvgImageAgeDays int `json:"avg_image_age_days"`
}

// NewScanner returns a scanner that audits container image references.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		podList, err := client.Clientset().CoreV1().Pods("").List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{}
		images := make(map[string]struct{})
		byImage := make(map[string]podRef)

		for _, pod := range podList.Items {
			for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				data.TotalContainers++
				img := c.Image
				images[img] = struct{}{}
				if _, ok := byImage[img]; !ok {
					byImage[img] = podRef{
						Namespace:      pod.Namespace,
						ServiceAccount: pod.Spec.ServiceAccountName,
						PullSecrets:    pullSecretNames(pod.Spec.ImagePullSecrets),
					}
				}

				var risks []string

				if isLatestOrNoTag(img) {
					data.LatestTag++
					risks = append(risks, "latest-or-no-tag")
				}
				if !strings.Contains(img, "@sha256:") {
					data.NoDigest++
					risks = append(risks, "no-digest-pin")
				}

				if len(risks) > 0 {
					data.ImageRisks = append(data.ImageRisks, ImageRisk{
						Namespace: pod.Namespace,
						Pod:       pod.Name,
						Container: c.Name,
						Image:     img,
						Risks:     risks,
					})
				}
			}
		}

		data.UniqueImages = len(images)

		sort.Slice(data.ImageRisks, func(i, j int) bool {
			return len(data.ImageRisks[i].Risks) > len(data.ImageRisks[j].Risks)
		})
		if len(data.ImageRisks) > 50 {
			data.ImageRisks = data.ImageRisks[:50]
		}

		if ProbeRegistriesEnabled() {
			fillProbeMetrics(ctx, client, byImage, &data)
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// pullSecretNames extracts secret names from a pod's spec.imagePullSecrets.
func pullSecretNames(refs []corev1.LocalObjectReference) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Name
	}
	return out
}

// fillProbeMetrics runs registry probing for every unique image and folds
// the aggregate counts back into data.
func fillProbeMetrics(ctx context.Context, client *kube.Client, byImage map[string]podRef, data *Data) {
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(probeTimeoutMS)*time.Millisecond*time.Duration(len(byImage)))
	defer cancel()
	results := probeImages(probeCtx, client, byImage)
	var totalAge time.Duration
	probed := 0
	for _, r := range results {
		if r.Err != nil {
			data.ImagesFailed++
			continue
		}
		data.ImagesProbed++
		if !r.CreatedAt.IsZero() {
			age := time.Since(r.CreatedAt)
			totalAge += age
			probed++
			days := int(age.Hours() / 24)
			if days > data.OldestImageAgeDays {
				data.OldestImageAgeDays = days
			}
		}
	}
	if probed > 0 {
		data.AvgImageAgeDays = int((totalAge / time.Duration(probed)).Hours() / 24)
	}
}

// isLatestOrNoTag returns true if the image uses :latest or has no tag at all.
func isLatestOrNoTag(image string) bool {
	// Remove digest if present.
	if idx := strings.Index(image, "@"); idx >= 0 {
		image = image[:idx]
	}
	// Check for :latest.
	if strings.HasSuffix(image, ":latest") {
		return true
	}
	// Check for no tag (no colon after the last slash).
	lastSlash := strings.LastIndex(image, "/")
	afterSlash := image
	if lastSlash >= 0 {
		afterSlash = image[lastSlash:]
	}
	return !strings.Contains(afterSlash, ":")
}
