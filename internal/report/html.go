package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
)

//go:embed templates/report.html
var templateFS embed.FS

// ClusterColors assigns a consistent color to each cluster for visual tracking.
var ClusterColors = []string{
	"#58a6ff", "#f85149", "#3fb950", "#d29922",
	"#bc8cff", "#39d353", "#f78166", "#8b949e",
}

// ScannerLabels maps scanner keys to human-readable names.
var ScannerLabels = map[string]string{
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
}

// htmlPayload is the data embedded in the HTML report as JSON. Everything the
// client-side JS needs to render the dashboard.
type htmlPayload struct {
	Report        *Report           `json:"report"`
	ClusterColors map[string]string `json:"clusterColors"`
	ScannerLabels map[string]string `json:"scannerLabels"`
}

// RenderHTML produces a self-contained HTML dashboard from a Report. The report
// data is embedded as a JSON blob and all rendering happens client-side in JS.
func RenderHTML(r *Report) ([]byte, error) {
	payload := htmlPayload{
		Report:        r,
		ClusterColors: make(map[string]string, len(r.Clusters)),
		ScannerLabels: ScannerLabels,
	}
	for i, c := range r.Clusters {
		payload.ClusterColors[c] = ClusterColors[i%len(ClusterColors)]
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
	if err := tmpl.Execute(&buf, template.JS(payloadJSON)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
