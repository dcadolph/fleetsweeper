// Package fleetdrift converts Fleetsweeper reports into FleetDriftReport
// Kubernetes custom resources, one per scanned cluster, and writes them to a
// local directory as YAML files. The intent is GitOps: an operator commits or
// reconciles the directory into a cluster, and Argo CD or Flux picks up the
// drift state as just another Kubernetes object.
//
// Fleetsweeper deliberately does not write to the clusters it scans. This
// package writes only to the local filesystem; what happens next is the
// operator's choice.
package fleetdrift

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// APIVersion is the FleetDriftReport CRD apiVersion. Bumped if and only if
// the resource schema changes in a backwards-incompatible way.
const APIVersion = "fleetsweeper.io/v1alpha1"

// Kind is the FleetDriftReport CRD kind.
const Kind = "FleetDriftReport"

// FleetDriftReport mirrors the FleetDriftReport CRD shape declared in
// deploy/crds/fleetdriftreport.yaml. Marshaling uses sigs.k8s.io/yaml so the
// emitted document matches the conventions Kubernetes tooling expects.
type FleetDriftReport struct {
	// APIVersion identifies the group/version of the resource.
	APIVersion string `json:"apiVersion"`
	// Kind identifies the resource type.
	Kind string `json:"kind"`
	// Metadata is the standard ObjectMeta subset relevant for GitOps reconciliation.
	Metadata Metadata `json:"metadata"`
	// Spec describes the cluster the report is about.
	Spec Spec `json:"spec"`
	// Status reflects findings and summary metrics.
	Status Status `json:"status"`
}

// Metadata is the minimal ObjectMeta projection needed for GitOps.
type Metadata struct {
	// Name uniquely identifies the report within its namespace.
	Name string `json:"name"`
	// Namespace places the report. When empty, callers may treat the CR as
	// cluster-scoped or apply with the GitOps tool's default namespace.
	Namespace string `json:"namespace,omitempty"`
	// Labels are propagated for label-selector queries by reconciliation tools.
	Labels map[string]string `json:"labels,omitempty"`
}

// Spec captures the scan identity and the cluster the report applies to.
type Spec struct {
	// Cluster is the kubeconfig context name of the cluster.
	Cluster string `json:"cluster"`
	// ScanID is the Fleetsweeper-assigned scan identifier.
	ScanID string `json:"scanId"`
	// ScanTime is when the scan executed.
	ScanTime time.Time `json:"scanTime"`
	// FleetScore is the fleet-wide score (0-100) computed for this scan.
	FleetScore FleetScoreSpec `json:"fleetScore"`
}

// FleetScoreSpec mirrors the report.FleetScore wire shape.
type FleetScoreSpec struct {
	// Score is the 0-100 fleet-wide health score.
	Score int `json:"score"`
	// Grade is the letter grade rollup.
	Grade string `json:"grade"`
}

// Status reflects the per-cluster findings and a small summary block.
type Status struct {
	// ObservedAt is when the findings were observed: the scan time, so regenerating a report
	// from the same scan yields the same object.
	ObservedAt time.Time `json:"observedAt"`
	// Summary holds the per-severity finding counts for this cluster.
	Summary Summary `json:"summary"`
	// Findings is the per-cluster list of findings ranked by severity.
	Findings []FindingSpec `json:"findings,omitempty"`
}

// Summary is the per-severity finding tally for the cluster.
type Summary struct {
	// Critical is the count of critical findings.
	Critical int `json:"critical"`
	// Warning is the count of warning findings.
	Warning int `json:"warning"`
	// Info is the count of info findings.
	Info int `json:"info"`
}

// FindingSpec is a single finding in the report's status.
type FindingSpec struct {
	// Severity is critical, warning, or info.
	Severity string `json:"severity"`
	// Scanner is the originating scanner name.
	Scanner string `json:"scanner"`
	// Title is the short human-readable name of the finding.
	Title string `json:"title"`
	// Description is the longer explanation.
	Description string `json:"description,omitempty"`
	// Affected names the resources implicated.
	Affected []string `json:"affected,omitempty"`
	// Remediation, when present, is the kubectl command and/or YAML manifest
	// that addresses the finding.
	Remediation *RemediationSpec `json:"remediation,omitempty"`
}

// RemediationSpec mirrors the report.Remediation wire shape.
type RemediationSpec struct {
	// Command is a kubectl invocation parameterized with the offending names.
	Command string `json:"command,omitempty"`
	// YAML is a baseline manifest the operator can apply.
	YAML string `json:"yaml,omitempty"`
	// RunbookURL is an optional internal runbook link.
	RunbookURL string `json:"runbookURL,omitempty"`
}

// ReportsFor builds one FleetDriftReport per cluster in the supplied
// report.Report. Fleet-scoped findings (Cluster == "fleet") are duplicated
// onto every cluster's report so a single GitOps reconciler does not have to
// know about an out-of-band aggregate object.
func ReportsFor(r *report.Report, scanID, namespace string) []FleetDriftReport {
	if r == nil {
		return nil
	}
	healthByName := map[string]report.ClusterHealth{}
	for _, h := range r.ClusterHealths {
		healthByName[h.Name] = h
	}
	findingsByCluster := report.GroupFindingsByCluster(r.Findings)

	scanTime, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		scanTime = time.Now().UTC()
	}
	score := FleetScoreSpec{Score: r.FleetScore.Score, Grade: r.FleetScore.Grade}

	out := make([]FleetDriftReport, 0, len(r.Clusters))
	for _, cluster := range r.Clusters {
		fs := append([]report.Finding{}, findingsByCluster[cluster]...)
		fs = append(fs, findingsByCluster["fleet"]...)
		out = append(out, FleetDriftReport{
			APIVersion: APIVersion,
			Kind:       Kind,
			Metadata: Metadata{
				Name:      util.SanitizeName(cluster),
				Namespace: namespace,
				Labels: map[string]string{
					"fleetsweeper.io/cluster":      cluster,
					"fleetsweeper.io/scan-id":      scanID,
					"app.kubernetes.io/managed-by": "fleetsweeper",
				},
			},
			Spec: Spec{
				Cluster:    cluster,
				ScanID:     scanID,
				ScanTime:   scanTime,
				FleetScore: score,
			},
			Status: Status{
				ObservedAt: scanTime,
				Summary:    summarize(fs),
				Findings:   toFindingSpecs(fs),
			},
		})
	}
	return out
}

// Write marshals the provided reports as YAML files into dir, one file per
// cluster named <sanitized-cluster>.yaml. The directory is created if it
// does not exist. Existing files for the same cluster are overwritten so the
// directory always reflects the latest scan.
func Write(reports []FleetDriftReport, dir string) error {
	if dir == "" {
		return fmt.Errorf("fleetdrift: output dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for _, r := range reports {
		path := filepath.Join(dir, r.Metadata.Name+".yaml")
		data, err := yaml.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", r.Metadata.Name, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// summarize tallies findings by severity.
func summarize(fs []report.Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Severity {
		case report.SeverityCritical:
			s.Critical++
		case report.SeverityWarning:
			s.Warning++
		case report.SeverityInfo:
			s.Info++
		}
	}
	return s
}

// toFindingSpecs converts report.Finding values into the CR-friendly spec.
func toFindingSpecs(fs []report.Finding) []FindingSpec {
	out := make([]FindingSpec, 0, len(fs))
	for _, f := range fs {
		spec := FindingSpec{
			Severity:    f.Severity,
			Scanner:     f.Scanner,
			Title:       f.Title,
			Description: f.Description,
			Affected:    append([]string{}, f.Affected...),
		}
		if f.Remediation != nil {
			spec.Remediation = &RemediationSpec{
				Command:    f.Remediation.Command,
				YAML:       f.Remediation.YAML,
				RunbookURL: f.Remediation.RunbookURL,
			}
		}
		out = append(out, spec)
	}
	return out
}
