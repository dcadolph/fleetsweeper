package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"sort"
)

//go:embed templates/report.html
var templateFS embed.FS

// ChartJS is the vendored Chart.js build. The standalone report inlines it so
// the file renders offline from file://, and the server serves the same bytes
// at /vendor/chart.min.js.
//
//go:embed templates/chart.min.js
var ChartJS []byte

// htmlTemplateData is what the report template renders.
type htmlTemplateData struct {
	// Payload is the report data as a JSON blob.
	Payload template.JS
	// ChartJS is the Chart.js source to inline.
	ChartJS template.JS
}

// clusterColors assigns a consistent color to each cluster for visual tracking.
var clusterColors = []string{
	"#58a6ff", "#f85149", "#3fb950", "#d29922",
	"#bc8cff", "#39d353", "#f78166", "#8b949e",
}

// scannerLabels maps scanner keys to human-readable names.
var scannerLabels = map[string]string{
	"version":           "Kubernetes Version",
	"namespaces":        "Namespaces",
	"crds":              "Custom Resource Definitions",
	"services":          "Services",
	"ingresses":         "Ingress Resources",
	"resources":         "Node Resources",
	"rbac":              "RBAC Configuration",
	"security":          "Pod Security Standards",
	"network-policies":  "Network Policies",
	"resource-quotas":   "Resource Quotas and Limits",
	"node-health":       "Node Health",
	"metrics":           "Resource Utilization",
	"events":            "Cluster Events",
	"workload-security": "Workload Security",
	"rbac-audit":        "RBAC Audit",
	"image-audit":       "Image Hygiene",
	"certs":             "Certificate Expiry",
	"deprecated-apis":   "Deprecated APIs",
	"workload-coverage": "PDB/HPA Coverage",
	"cluster-info":      "Node OS/Kernel Drift",
	"admission":         "Admission Webhooks",
	"geo":               "Geographic Location",
	"vulnerabilities":   "Image Vulnerabilities",
	"policy-reports":    "Policy Reports",
}

// scannerDescriptions maps scanner keys to one line on what each checks.
var scannerDescriptions = map[string]string{
	"version":           "API server version, with semver-aware skew severity.",
	"namespaces":        "Namespace lists, labels, and Pod Security Standards labels.",
	"crds":              "Installed CustomResourceDefinitions, compared as a set of names.",
	"services":          "Services across all namespaces, their types and ports.",
	"ingresses":         "Ingress resources, their classes, TLS, and hosts.",
	"resources":         "Node count, allocatable CPU and memory, and scheduling status.",
	"rbac":              "ClusterRoles, Roles, and their bindings.",
	"security":          "Pod Security Standards enforcement labels on every namespace.",
	"network-policies":  "NetworkPolicy coverage per namespace.",
	"resource-quotas":   "ResourceQuota and LimitRange objects.",
	"node-health":       "Node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure.",
	"metrics":           "CPU and memory utilization from metrics-server.",
	"events":            "Warning events in the last hour, by reason.",
	"workload-security": "Privileged containers, host namespaces, added capabilities, and root users.",
	"rbac-audit":        "Cluster-admin bindings, wildcard rules, and default service account grants.",
	"image-audit":       "Images on :latest or no tag, without digest pins, or from deprecated registries.",
	"certs":             "Expiry of TLS Secrets, Ingress TLS, and webhook CA bundles.",
	"deprecated-apis":   "API versions in use that upcoming Kubernetes releases deprecate or remove.",
	"workload-coverage": "PodDisruptionBudget and HorizontalPodAutoscaler coverage of replicated workloads.",
	"cluster-info":      "Node OS, kernel, runtime, and kubelet version drift within a cluster.",
	"admission":         "Webhook configurations with no healthy endpoints or expiring CA bundles.",
	"geo":               "Cluster location from node topology region and zone labels.",
	"vulnerabilities":   "Image vulnerability counts from Trivy Operator VulnerabilityReports.",
	"policy-reports":    "Fail and warn results from Kyverno, Gatekeeper, and other PolicyReport writers.",
}

// ScannerInfo describes one scanner for clients that list them.
type ScannerInfo struct {
	// ID is the scanner key used in reports and findings.
	ID string `json:"id"`
	// Label is the human-readable name.
	Label string `json:"label"`
	// Description says in one line what the scanner checks.
	Description string `json:"description"`
	// Category is the report category the scanner belongs to.
	Category string `json:"category"`
}

// ScannerCatalog returns every scanner with a label, sorted by ID.
func ScannerCatalog() []ScannerInfo {
	category := map[string]string{}
	for _, c := range Categories() {
		for _, s := range c.Scanners {
			category[s] = c.Name
		}
	}
	out := make([]ScannerInfo, 0, len(scannerLabels))
	for id, label := range scannerLabels {
		out = append(out, ScannerInfo{ID: id, Label: label, Description: scannerDescriptions[id], Category: category[id]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// htmlPayload is the data embedded in the HTML report as JSON. Everything the
// client-side JS needs to render the dashboard.
type htmlPayload struct {
	// Report is the report the dashboard renders.
	Report *Report `json:"report"`
	// ClusterColors maps cluster name to its display color.
	ClusterColors map[string]string `json:"clusterColors"`
	// ScannerLabels maps scanner name to its display label.
	ScannerLabels map[string]string `json:"scannerLabels"`
}

// RenderHTML produces a self-contained HTML dashboard from a Report. The report
// data is embedded as a JSON blob and all rendering happens client-side in JS.
func RenderHTML(r *Report) ([]byte, error) {
	payload := htmlPayload{
		Report:        r,
		ClusterColors: make(map[string]string, len(r.Clusters)),
		ScannerLabels: scannerLabels,
	}
	for i, c := range r.Clusters {
		payload.ClusterColors[c] = clusterColors[i%len(clusterColors)]
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("report.html").ParseFS(templateFS, "templates/report.html")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, htmlTemplateData{Payload: template.JS(payloadJSON), ChartJS: template.JS(ChartJS)}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
