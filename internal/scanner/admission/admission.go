// Package admission audits MutatingWebhookConfigurations and
// ValidatingWebhookConfigurations for two failure modes that silently break
// clusters: webhooks whose backing service has zero healthy endpoints, and
// webhooks whose caBundle is expiring soon. Failing webhooks frequently take
// the cluster offline at admission time; surfacing them in a fleet report is
// pure pre-incident win.
package admission

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "admission"

// caExpirySoonDays controls when a webhook's CA bundle is reported as expiring.
const caExpirySoonDays = 30

// Webhook describes one admission webhook entry.
type Webhook struct {
	// Configuration is the parent webhook configuration name.
	Configuration string `json:"configuration"`
	// Webhook is the individual webhook name.
	Webhook string `json:"webhook"`
	// Type is "Mutating" or "Validating".
	Type string `json:"type"`
	// Service is "namespace/name" when configured, or empty for URL-based webhooks.
	Service string `json:"service,omitempty"`
	// URL is the explicit URL when configured, otherwise empty.
	URL string `json:"url,omitempty"`
	// EndpointsHealthy is true when the backing Service has at least one ready endpoint.
	// Always false for URL-based webhooks (we cannot probe them safely).
	EndpointsHealthy bool `json:"endpoints_healthy"`
	// FailurePolicy is "Fail" or "Ignore".
	FailurePolicy string `json:"failure_policy"`
	// CABundleNotAfter is the earliest expiry across the caBundle, or zero if none.
	CABundleNotAfter time.Time `json:"ca_bundle_not_after,omitempty"`
	// CABundleDaysRemaining is the days until the earliest cert expires; -1 when unknown.
	CABundleDaysRemaining int `json:"ca_bundle_days_remaining"`
}

// Data holds admission webhook audit results for one cluster.
type Data struct {
	// TotalWebhooks is the count of webhooks inspected (mutating + validating).
	TotalWebhooks int `json:"total_webhooks"`
	// UnhealthyWebhooks is the count whose service has zero ready endpoints.
	UnhealthyWebhooks int `json:"unhealthy_webhooks"`
	// ExpiringCABundles is the count whose CA bundle expires within caExpirySoonDays.
	ExpiringCABundles int `json:"expiring_ca_bundles"`
	// FailClosedWebhooks counts webhooks with failurePolicy=Fail (cluster outage on fault).
	FailClosedWebhooks int `json:"fail_closed_webhooks"`
	// Webhooks lists per-webhook detail, capped at 100 entries.
	Webhooks []Webhook `json:"webhooks"`
}

// NewScanner returns a scanner that audits admission webhook health.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		data := Data{}
		now := time.Now()

		mwh, err := client.Clientset().AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err == nil {
			for i := range mwh.Items {
				cfg := &mwh.Items[i]
				for _, wh := range cfg.Webhooks {
					data.Webhooks = append(data.Webhooks, buildWebhook(ctx, client, cfg.Name, "Mutating", wh.Name, wh.ClientConfig, wh.FailurePolicy, now))
				}
			}
		}
		vwh, err := client.Clientset().AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err == nil {
			for i := range vwh.Items {
				cfg := &vwh.Items[i]
				for _, wh := range cfg.Webhooks {
					data.Webhooks = append(data.Webhooks, buildValidatingWebhook(ctx, client, cfg.Name, wh, now))
				}
			}
		}

		data.TotalWebhooks = len(data.Webhooks)
		for _, w := range data.Webhooks {
			if w.Service != "" && !w.EndpointsHealthy {
				data.UnhealthyWebhooks++
			}
			if w.CABundleDaysRemaining >= 0 && w.CABundleDaysRemaining < caExpirySoonDays {
				data.ExpiringCABundles++
			}
			if w.FailurePolicy == "Fail" {
				data.FailClosedWebhooks++
			}
		}

		sort.Slice(data.Webhooks, func(i, j int) bool {
			return data.Webhooks[i].Configuration+data.Webhooks[i].Webhook < data.Webhooks[j].Configuration+data.Webhooks[j].Webhook
		})
		if len(data.Webhooks) > 100 {
			data.Webhooks = data.Webhooks[:100]
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// buildWebhook resolves a mutating webhook into the audit-friendly Webhook
// struct, including endpoint health and CA bundle expiry.
func buildWebhook(ctx context.Context, client *kube.Client, cfgName, kind, name string, cc admissionregv1.WebhookClientConfig, failurePolicy *admissionregv1.FailurePolicyType, now time.Time) Webhook {
	w := Webhook{
		Configuration:         cfgName,
		Webhook:               name,
		Type:                  kind,
		CABundleDaysRemaining: -1,
	}
	if failurePolicy != nil {
		w.FailurePolicy = string(*failurePolicy)
	}
	if cc.Service != nil {
		w.Service = fmt.Sprintf("%s/%s", cc.Service.Namespace, cc.Service.Name)
		w.EndpointsHealthy = endpointsHealthy(ctx, client, cc.Service.Namespace, cc.Service.Name)
	}
	if cc.URL != nil {
		w.URL = *cc.URL
	}
	if exp, ok := earliestExpiry(cc.CABundle); ok {
		w.CABundleNotAfter = exp
		w.CABundleDaysRemaining = int(exp.Sub(now).Hours() / 24)
	}
	return w
}

// buildValidatingWebhook is the validating-webhook counterpart of buildWebhook.
func buildValidatingWebhook(ctx context.Context, client *kube.Client, cfgName string, wh admissionregv1.ValidatingWebhook, now time.Time) Webhook {
	return buildWebhook(ctx, client, cfgName, "Validating", wh.Name, wh.ClientConfig, wh.FailurePolicy, now)
}

// endpointsHealthy reports whether the named Service in namespace has at
// least one ready endpoint. URL-based webhooks always return false because
// we cannot safely probe arbitrary external endpoints during a scan.
func endpointsHealthy(ctx context.Context, client *kube.Client, namespace, name string) bool {
	ep, err := client.Clientset().CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false
	}
	for _, sub := range ep.Subsets {
		if len(sub.Addresses) > 0 {
			return true
		}
	}
	_ = corev1.SchemeGroupVersion
	return false
}

// earliestExpiry returns the earliest NotAfter across all certificates in a
// PEM-encoded bundle. Returns ok=false when no certificates were decoded.
func earliestExpiry(bundle []byte) (time.Time, bool) {
	rest := bundle
	var earliest time.Time
	found := false
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if !found || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
			found = true
		}
	}
	return earliest, found
}
