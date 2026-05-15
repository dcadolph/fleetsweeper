package imageaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

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
}

// NewScanner returns a scanner that audits container image references.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		podList, err := client.Clientset().CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{}
		images := make(map[string]struct{})

		for _, pod := range podList.Items {
			for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				data.TotalContainers++
				img := c.Image
				images[img] = struct{}{}

				var risks []string

				// Check for :latest or no tag.
				if isLatestOrNoTag(img) {
					data.LatestTag++
					risks = append(risks, "latest-or-no-tag")
				}

				// Check for digest pin.
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

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
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
