// Package certs scans TLS Secrets, Ingress TLS references, and admission
// webhook caBundles for upcoming expiry. Operators routinely lose service to
// a cert that nobody had a calendar reminder for; surfacing the soonest
// expiring cert per cluster in a comparison report removes that surprise.
package certs

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"

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

// tlsSecretSelector asks the apiserver for TLS Secrets only, so the scan never pulls every
// Secret's payload in the cluster.
const tlsSecretSelector = "type=" + string(corev1.SecretTypeTLS)

// NewScanner returns a scanner that enumerates TLS certificates across the cluster. A list that
// fails does not abort the scan: the result keeps whatever was read and is StateDegraded with a
// reason naming the failed list. When every list fails, the scan errors rather than reporting a
// cluster with zero certificates.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		data := Data{Soonest: -1}
		now := time.Now()
		var cov scanner.Coverage
		cs := client.Clientset()

		secretOpts := scanner.CacheReadOptions()
		secretOpts.FieldSelector = tlsSecretSelector
		secrets, err := scanner.ListAll(ctx, secretOpts, cs.CoreV1().Secrets("").List,
			func(l *corev1.SecretList) []corev1.Secret { return l.Items })
		if cov.Observe("secrets", err) {
			for i := range secrets {
				appendSecretCerts(&data, &secrets[i], now)
			}
		}

		mwh, err := scanner.ListAll(ctx, scanner.CacheReadOptions(),
			cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List,
			func(l *admissionregv1.MutatingWebhookConfigurationList) []admissionregv1.MutatingWebhookConfiguration {
				return l.Items
			})
		if cov.Observe("mutating webhook configurations", err) {
			for i := range mwh {
				appendWebhookCAs(&data, &mwh[i], now)
			}
		}

		vwh, err := scanner.ListAll(ctx, scanner.CacheReadOptions(),
			cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List,
			func(l *admissionregv1.ValidatingWebhookConfigurationList) []admissionregv1.ValidatingWebhookConfiguration {
				return l.Items
			})
		if cov.Observe("validating webhook configurations", err) {
			for i := range vwh {
				appendValidatingCAs(&data, &vwh[i], now)
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

		data.Certs = scanner.TopN(data.Certs, 100, compareCerts)

		return cov.Finish(Name, data)
	})
}

// appendSecretCerts records every certificate in a TLS Secret's tls.crt. The type check stays
// even though the list is field-selected, because a client that ignores field selectors would
// otherwise hand opaque Secrets to the PEM parser.
func appendSecretCerts(data *Data, s *corev1.Secret, now time.Time) {
	if s.Type != corev1.SecretTypeTLS {
		return
	}
	crt, ok := s.Data["tls.crt"]
	if !ok {
		return
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

// compareCerts orders certificates by days remaining, soonest first, then by namespace, name,
// and kind.
func compareCerts(a, b Cert) int {
	return cmp.Or(
		cmp.Compare(a.DaysRemaining, b.DaysRemaining),
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Kind, b.Kind),
	)
}
