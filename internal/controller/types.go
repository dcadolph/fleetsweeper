// Package controller reconciles ClusterScan custom resources by triggering
// scans on the configured cadence and writing the outcome back to the resource
// status. It uses an unstructured dynamic client so the operator can ship
// without code generation steps.
package controller

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersionResource for the ClusterScan CRD.
var ClusterScanGVR = schema.GroupVersionResource{
	Group:    "fleetsweeper.io",
	Version:  "v1alpha1",
	Resource: "clusterscans",
}

// ClusterScanSpec mirrors the spec fields declared in deploy/crds/clusterscan.yaml.
// Only the fields the controller reads are typed; the rest are passed through
// unstructured maps so additive schema changes do not require code changes.
type ClusterScanSpec struct {
	// Contexts are kubeconfig context names to include in the scan.
	Contexts []string `json:"contexts,omitempty"`
	// Group is the name of a fleetsweeper group whose members will be scanned.
	Group string `json:"group,omitempty"`
	// Interval is a Go duration string between scans, for example "15m".
	Interval string `json:"interval,omitempty"`
	// Scanners restricts the scan to the named scanners. Empty runs all.
	Scanners []string `json:"scanners,omitempty"`
	// Emit selects which artefacts to emit after each scan.
	Emit EmitOptions `json:"emit,omitempty"`
	// Paused, when true, makes the controller skip reconciliation.
	Paused bool `json:"paused,omitempty"`
}

// EmitOptions selects which sinks receive scan outputs.
type EmitOptions struct {
	// FleetDriftReport emits FleetDriftReport YAMLs to the configured directory.
	FleetDriftReport bool `json:"fleetDriftReport,omitempty"`
	// PolicyReport emits wgpolicyk8s.io PolicyReports to the configured directory.
	PolicyReport bool `json:"policyReport,omitempty"`
	// Slack delivers new critical findings to the configured webhook URL.
	Slack bool `json:"slack,omitempty"`
}

// ClusterScanStatus mirrors the status fields declared in the CRD.
type ClusterScanStatus struct {
	// Phase is the current reconciliation phase.
	Phase string `json:"phase,omitempty"`
	// LastScanID is the most recently completed scan identifier.
	LastScanID string `json:"lastScanID,omitempty"`
	// LastScanTime is when the most recent scan completed.
	LastScanTime *time.Time `json:"lastScanTime,omitempty"`
	// NextScanTime is when the controller intends to run the next scan.
	NextScanTime *time.Time `json:"nextScanTime,omitempty"`
	// ObservedScore is the fleet score from the most recent scan.
	ObservedScore int `json:"observedScore,omitempty"`
	// ObservedGrade is the letter grade from the most recent scan.
	ObservedGrade string `json:"observedGrade,omitempty"`
	// ObservedCritical is the count of critical findings.
	ObservedCritical int `json:"observedCritical,omitempty"`
	// ObservedWarning is the count of warning findings.
	ObservedWarning int `json:"observedWarning,omitempty"`
	// ObservedClusters is the number of clusters that returned data.
	ObservedClusters int `json:"observedClusters,omitempty"`
	// Message is a human-readable summary of the last reconciliation.
	Message string `json:"message,omitempty"`
	// Conditions are standard Kubernetes status conditions.
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition is a standard Kubernetes status condition.
type Condition struct {
	// Type names the condition (for example "Ready").
	Type string `json:"type"`
	// Status is "True", "False", or "Unknown".
	Status string `json:"status"`
	// Reason is a CamelCase reason for the transition.
	Reason string `json:"reason,omitempty"`
	// Message is human-readable detail.
	Message string `json:"message,omitempty"`
	// LastTransitionTime is when the condition last changed.
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// Reconciliation phases.
const (
	// PhasePending indicates the controller has not yet run a scan for the resource.
	PhasePending = "Pending"
	// PhaseRunning indicates a scan is currently executing.
	PhaseRunning = "Running"
	// PhaseSucceeded indicates the last scan completed without error.
	PhaseSucceeded = "Succeeded"
	// PhaseFailed indicates the last scan ended with an error.
	PhaseFailed = "Failed"
	// PhasePaused indicates spec.paused is true.
	PhasePaused = "Paused"
)
