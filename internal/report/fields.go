package report

// Polarity says which direction of a numeric field is the worse one.
type Polarity int

const (
	// PolarityNone means neither direction is better, so the difference itself is the fact.
	PolarityNone Polarity = iota
	// UpIsBad means a higher value is worse.
	UpIsBad
	// DownIsBad means a lower value is worse.
	DownIsBad
)

// FieldRef names one field of one scanner's data.
type FieldRef struct {
	// Scanner is the scanner name, e.g. "node-health".
	Scanner string
	// Field is the JSON field name in that scanner's data, e.g. "not_ready_nodes".
	Field string
}

// fieldSpec declares what one scanner field means to the report. A field with no spec is still
// measured and reported, at info severity with no polarity.
type fieldSpec struct {
	FieldRef
	// Severity is SeverityCritical or SeverityWarning for a declared divergence or outlier
	// severity, or "" for info.
	Severity string
	// Polarity says which side of the norm is worse.
	Polarity Polarity
	// RedundantWith lists the fields whose findings already state this field's fact.
	RedundantWith []FieldRef
	// CountedBy is the absolute rule that counts this field, or "" when none does.
	CountedBy string
	// Trend marks the field as tracked for trends and self-drift.
	Trend bool
	// Projection derives this set field from an object array on the same scanner, or is nil.
	Projection *setProjection
	// AvailabilityGated marks a scanner whose counts measure nothing on a cluster without the
	// scanned feature. It is set on every spec of such a scanner and applies scanner-wide.
	AvailabilityGated bool
}

// ref builds a FieldRef.
func ref(scanner, field string) FieldRef {
	return FieldRef{Scanner: scanner, Field: field}
}

// gitVersion is the field every other version field restates.
var gitVersion = []FieldRef{ref("version", "git_version")}

// fieldSpecs is the one place a scanner field's severity, polarity, redundancy, trend
// tracking, counting rule, set projection, and availability gate are declared. Trend entries
// keep their order, since trends are reported in it.
var fieldSpecs = []fieldSpec{
	{
		FieldRef: ref("metrics", "avg_cpu_percent"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
		Trend:    true,
	},
	{
		FieldRef: ref("metrics", "avg_memory_percent"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
		Trend:    true,
	},
	{
		FieldRef: ref("metrics", "max_cpu_percent"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
		Trend:    true,
	},
	{
		FieldRef: ref("metrics", "max_memory_percent"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
		Trend:    true,
	},

	{
		FieldRef: ref("node-health", "unhealthy_nodes"),
		Severity: SeverityCritical,
		Polarity: UpIsBad,
		Trend:    true,
		RedundantWith: []FieldRef{
			ref("node-health", "memory_pressure_nodes"),
			ref("node-health", "disk_pressure_nodes"),
			ref("node-health", "pid_pressure_nodes"),
			ref("node-health", "not_ready_nodes"),
		},
	},
	{
		FieldRef:  ref("node-health", "memory_pressure_nodes"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		Trend:     true,
		CountedBy: "node-health/memory-pressure",
	},
	{
		FieldRef:  ref("node-health", "not_ready_nodes"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		Trend:     true,
		CountedBy: "node-health/not-ready",
	},
	{
		FieldRef:  ref("node-health", "disk_pressure_nodes"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "node-health/disk-pressure",
	},
	{
		FieldRef: ref("node-health", "pid_pressure_nodes"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
	},
	{
		FieldRef: ref("node-health", "unschedulable_nodes"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
	},

	{
		FieldRef:  ref("events", "warning_events"),
		Polarity:  UpIsBad,
		Trend:     true,
		CountedBy: "events/warning-volume",
	},

	{
		FieldRef:  ref("certs", "critical"),
		Polarity:  UpIsBad,
		CountedBy: "certs/expiring-7d",
	},
	{
		FieldRef:  ref("certs", "warning"),
		Polarity:  UpIsBad,
		CountedBy: "certs/expiring-30d",
	},
	{
		FieldRef:      ref("certs", "soonest_days"),
		Polarity:      DownIsBad,
		RedundantWith: []FieldRef{ref("certs", "warning"), ref("certs", "critical")},
	},

	{FieldRef: ref("security", "enforced_count"), Severity: SeverityCritical, Polarity: DownIsBad},
	{
		FieldRef:  ref("security", "unenforced_count"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		Trend:     true,
		CountedBy: "security/psa-unenforced",
	},

	{FieldRef: ref("network-policies", "count")},
	{
		FieldRef:  ref("network-policies", "namespaces_without_policies"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		Trend:     true,
		CountedBy: "network-policies/no-policy",
	},

	{
		FieldRef: ref("resources", "unschedulable_nodes"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
		Trend:    true,
	},
	{FieldRef: ref("resources", "node_count"), Severity: SeverityWarning},
	{FieldRef: ref("resources", "ready_nodes"), Severity: SeverityWarning, Polarity: DownIsBad},

	{
		FieldRef:  ref("workload-security", "privileged_containers"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		CountedBy: "workload-security/privileged",
	},
	{
		FieldRef:  ref("workload-security", "host_network_pods"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		CountedBy: "workload-security/host-namespaces",
	},
	{
		FieldRef:  ref("workload-security", "host_pid_pods"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		CountedBy: "workload-security/host-namespaces",
	},
	{
		FieldRef:  ref("workload-security", "run_as_root_containers"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "workload-security/run-as-root",
	},
	{
		FieldRef:  ref("workload-security", "capability_additions"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "workload-security/capability-add",
	},
	{
		FieldRef: ref("workload-security", "allow_privilege_escalation"),
		Severity: SeverityWarning,
		Polarity: UpIsBad,
	},

	{
		FieldRef:  ref("rbac-audit", "cluster_admin_bindings"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		CountedBy: "rbac-audit/cluster-admin-binding",
	},
	{
		FieldRef:  ref("rbac-audit", "wildcard_rules"),
		Severity:  SeverityCritical,
		Polarity:  UpIsBad,
		CountedBy: "rbac-audit/wildcard-rule",
	},
	{
		FieldRef:  ref("rbac-audit", "default_sa_bindings"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "rbac-audit/default-sa-binding",
	},

	{FieldRef: ref("version", "git_version"), Severity: SeverityWarning},
	{FieldRef: ref("version", "minor"), Severity: SeverityWarning, RedundantWith: gitVersion},
	{FieldRef: ref("deprecated-apis", "server_version"), RedundantWith: gitVersion},
	{FieldRef: ref("cluster-info", "kubelet_versions"), RedundantWith: gitVersion},
	{FieldRef: ref("deprecated-apis", "total_instances"), CountedBy: "deprecated-apis/in-use"},

	{FieldRef: ref("namespaces", "count"), Severity: SeverityWarning},
	{FieldRef: ref("services", "count"), Severity: SeverityWarning},
	{
		FieldRef: ref("services", "service_names"),
		Projection: &setProjection{
			From:   "services",
			Member: memberOf("namespace", "name"),
			Build:  memberObject("namespace", "name"),
		},
	},
	{FieldRef: ref("ingresses", "count")},
	{
		FieldRef: ref("ingresses", "ingress_classes"),
		Projection: &setProjection{
			From:      "ingresses",
			Member:    memberOf("ingress_class_name"),
			SkipEmpty: true,
		},
	},
	{FieldRef: ref("crds", "count")},
	{
		FieldRef: ref("crds", "crd_names"),
		Severity: SeverityWarning,
		Projection: &setProjection{
			From:   "crds",
			Member: memberOf("name"),
			Build:  memberObject("name"),
		},
	},

	{FieldRef: ref("rbac", "cluster_role_count"), Severity: SeverityWarning},
	{FieldRef: ref("rbac", "cluster_role_binding_count"), Severity: SeverityWarning},

	{
		FieldRef: ref("resource-quotas", "quota_count"),
		Severity: SeverityWarning,
		Polarity: DownIsBad,
	},
	{
		FieldRef:  ref("resource-quotas", "namespaces_with_quotas"),
		Severity:  SeverityWarning,
		Polarity:  DownIsBad,
		CountedBy: "resource-quotas/no-quota",
	},

	{
		FieldRef:  ref("image-audit", "latest_tag"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "image-audit/latest-tag",
	},
	{
		FieldRef:  ref("image-audit", "no_digest"),
		Severity:  SeverityWarning,
		Polarity:  UpIsBad,
		CountedBy: "image-audit/no-digest",
	},

	{
		FieldRef:          ref("vulnerabilities", "critical"),
		Severity:          SeverityWarning,
		Polarity:          UpIsBad,
		CountedBy:         "vulnerabilities/critical-present",
		AvailabilityGated: true,
	},
	{
		FieldRef:          ref("policy-reports", "total_fail"),
		Severity:          SeverityWarning,
		Polarity:          UpIsBad,
		AvailabilityGated: true,
	},

	{
		FieldRef:  ref("workload-coverage", "missing_pdb"),
		Polarity:  UpIsBad,
		CountedBy: "workload-coverage/missing-pdb",
	},
	{
		FieldRef:  ref("workload-coverage", "missing_hpa"),
		Polarity:  UpIsBad,
		CountedBy: "workload-coverage/missing-hpa",
	},
	{
		FieldRef:  ref("admission", "unhealthy_webhooks"),
		Polarity:  UpIsBad,
		CountedBy: "admission/no-healthy-endpoints",
	},

	{FieldRef: ref("version", "major")},
}

// The tables below are views of fieldSpecs for the code that reads them.
var (
	// criticalFields maps scanner names to fields whose divergence or outlier is critical.
	criticalFields = severityFields(SeverityCritical)
	// warningFields maps scanner names to fields whose divergence or outlier is a warning.
	warningFields = severityFields(SeverityWarning)
	// trendFields lists the fields tracked for trends and self-drift, in declaration order.
	trendFields = trackedFields()
	// setProjections maps a scanner to the set field derived from its object array.
	setProjections = projections()
	// availabilityGated lists scanners whose counts are left out where the feature is absent.
	availabilityGated = gatedScanners()
)

// trendField is one field tracked for trends, with the direction that counts as worsening.
type trendField struct {
	// Scanner is the scanner name.
	Scanner string
	// Field is the JSON field name.
	Field string
	// UpIsBad reports whether a rising value is worsening.
	UpIsBad bool
}

// lookupField returns the spec for scanner/field and whether one is declared.
func lookupField(scanner, field string) (fieldSpec, bool) {
	for _, s := range fieldSpecs {
		if s.Scanner == scanner && s.Field == field {
			return s, true
		}
	}
	return fieldSpec{}, false
}

// DeclaredField reports whether scanner/field has an entry in the field registry.
func DeclaredField(scanner, field string) bool {
	_, ok := lookupField(scanner, field)
	return ok
}

// severityFields returns the scanner-to-field set of every spec with severity sev.
func severityFields(sev string) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, s := range fieldSpecs {
		if s.Severity != sev {
			continue
		}
		if out[s.Scanner] == nil {
			out[s.Scanner] = make(map[string]struct{})
		}
		out[s.Scanner][s.Field] = struct{}{}
	}
	return out
}

// trackedFields returns the trend-tracked specs in declaration order.
func trackedFields() []trendField {
	var out []trendField
	for _, s := range fieldSpecs {
		if s.Trend {
			out = append(out, trendField{
				Scanner: s.Scanner, Field: s.Field, UpIsBad: s.Polarity == UpIsBad,
			})
		}
	}
	return out
}

// projections returns the set projection of each scanner that declares one, with To set to
// the declaring field.
func projections() map[string]setProjection {
	out := make(map[string]setProjection)
	for _, s := range fieldSpecs {
		if s.Projection == nil {
			continue
		}
		p := *s.Projection
		p.To = s.Field
		out[s.Scanner] = p
	}
	return out
}

// gatedScanners returns the scanners any spec marks as availability-gated.
func gatedScanners() map[string]struct{} {
	out := make(map[string]struct{})
	for _, s := range fieldSpecs {
		if s.AvailabilityGated {
			out[s.Scanner] = struct{}{}
		}
	}
	return out
}
