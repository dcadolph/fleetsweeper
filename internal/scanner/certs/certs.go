// Package certs scans TLS Secrets, Ingress TLS references, and admission
// webhook caBundles for upcoming expiry. Operators routinely lose service to
// a cert that nobody had a calendar reminder for; surfacing the soonest
// expiring cert per cluster in a comparison report removes that surprise.
package certs

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
const Name = "certs"

// criticalDays is the threshold below which a cert is reported critical.
const criticalDays = 7

// warningDays is the threshold below which a cert is reported warning.
const warningDays = 30

// infoDays is the threshold below which a cert is reported info (visibility only).
const infoDays = 90

// Cert describes a single TLS certificate observed in the cluster.
type Cert struct {
	// Name is the secret or webhook configuration name.
	Name string `json:"name"`
	// Namespace is empty for cluster-scoped resources (webhook configurations).
	Namespace string `json:"namespace,omitempty"`
	// Kind is "Secret", "MutatingWebhookConfiguration", or "ValidatingWebhookConfiguration".
	Kind string `json:"kind"`
	// Subject is the certificate subject common name when parseable.
	Subject string `json:"subject,omitempty"`
	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after"`
	// DaysRemaining is the number of days until expiry.
	DaysRemaining int `json:"days_remaining"`
}

// Data holds certificate expiry results for one cluster.
type Data struct {
	// TotalCerts is the number of certificates inspected.
	TotalCerts int `json:"total_certs"`
	// Critical is the count of certs expiring within criticalDays.
	Critical int `json:"critical"`
	// Warning is the count of certs expiring within warningDays.
	Warning int `json:"warning"`
	// Info is the count of certs expiring within infoDays.
	Info int `json:"info"`
	// Soonest is the lowest DaysRemaining observed; -1 when no certs were found.
	Soonest int `json:"soonest_days"`
	// Certs lists individual certificate records.
	Certs []Cert `json:"certs"`
}

// NewScanner returns a scanner that enumerates TLS certificates across the
// cluster. Errors fetching one source do not abort the whole scan; the result
// reflects whatever was successfully read.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		data := Data{Soonest: -1}
		now := time.Now()

		secrets, err := client.Clientset().CoreV1().Secrets("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err == nil {
			for i := range secrets.Items {
				s := &secrets.Items[i]
				if s.Type != corev1.SecretTypeTLS {
					continue
				}
				crt, ok := s.Data["tls.crt"]
				if !ok {
					continue
				}
				for _, cert := range parsePEM(crt) {
					data.Certs = append(data.Certs, Cert{
						Name:          s.Name,
						Namespace:     s.Namespace,
						Kind:          "Secret",
						Subject:       cert.Subject.CommonName,
						NotAfter:      cert.NotAfter,
						DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
					})
				}
			}
		}

		mwh, err := client.Clientset().AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err == nil {
			for i := range mwh.Items {
				appendWebhookCAs(&data, &mwh.Items[i], now)
			}
		}

		vwh, err := client.Clientset().AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err == nil {
			for i := range vwh.Items {
				appendValidatingCAs(&data, &vwh.Items[i], now)
			}
		}

		data.TotalCerts = len(data.Certs)
		for _, c := range data.Certs {
			switch {
			case c.DaysRemaining < criticalDays:
				data.Critical++
			case c.DaysRemaining < warningDays:
				data.Warning++
			case c.DaysRemaining < infoDays:
				data.Info++
			}
			if data.Soonest == -1 || c.DaysRemaining < data.Soonest {
				data.Soonest = c.DaysRemaining
			}
		}

		sort.Slice(data.Certs, func(i, j int) bool {
			return data.Certs[i].DaysRemaining < data.Certs[j].DaysRemaining
		})
		if len(data.Certs) > 100 {
			data.Certs = data.Certs[:100]
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// parsePEM decodes a PEM-encoded byte slice into a slice of x509.Certificate.
// Bytes that do not decode are skipped silently so a single malformed entry
// does not lose every cert in the bundle.
func parsePEM(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for len(b) > 0 {
		block, rest := pem.Decode(b)
		if block == nil {
			return out
		}
		b = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	return out
}

// appendWebhookCAs walks a MutatingWebhookConfiguration's webhooks and
// records every caBundle's expiry.
func appendWebhookCAs(data *Data, mwc *admissionregv1.MutatingWebhookConfiguration, now time.Time) {
	for _, wh := range mwc.Webhooks {
		for _, cert := range parsePEM(wh.ClientConfig.CABundle) {
			data.Certs = append(data.Certs, Cert{
				Name:          fmt.Sprintf("%s/%s", mwc.Name, wh.Name),
				Kind:          "MutatingWebhookConfiguration",
				Subject:       cert.Subject.CommonName,
				NotAfter:      cert.NotAfter,
				DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
			})
		}
	}
}

// appendValidatingCAs walks a ValidatingWebhookConfiguration's webhooks and
// records every caBundle's expiry.
func appendValidatingCAs(data *Data, vwc *admissionregv1.ValidatingWebhookConfiguration, now time.Time) {
	for _, wh := range vwc.Webhooks {
		for _, cert := range parsePEM(wh.ClientConfig.CABundle) {
			data.Certs = append(data.Certs, Cert{
				Name:          fmt.Sprintf("%s/%s", vwc.Name, wh.Name),
				Kind:          "ValidatingWebhookConfiguration",
				Subject:       cert.Subject.CommonName,
				NotAfter:      cert.NotAfter,
				DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
			})
		}
	}
}
