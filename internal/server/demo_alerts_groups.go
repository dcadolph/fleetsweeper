package server

import (
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoGroups builds cluster groups from the synthetic fleet's roles so the
// Groups page shows meaningful membership in demo mode instead of an empty list.
func demoGroups() []store.GroupRecord {
	byRole := make(map[string][]string)
	for _, p := range demoPoints() {
		role := roleOf(p.Cluster)
		byRole[role] = append(byRole[role], p.Cluster)
	}
	labels := []struct {
		Role string
		Name string
	}{
		{"prod", "production"},
		{"retail", "retail-sites"},
		{"edge", "edge"},
		{"nonprod", "non-production"},
	}
	out := make([]store.GroupRecord, 0, len(labels))
	for _, l := range labels {
		if members := byRole[l.Role]; len(members) > 0 {
			out = append(out, store.GroupRecord{Name: l.Name, Clusters: members})
		}
	}
	return out
}

// demoAlerts synthesizes a spread of inbound alerts (AlertManager and Falco,
// firing and resolved, critical and warning) so the Alerts page demonstrates
// what live alert ingestion looks like without any real integration.
func demoAlerts() []store.AlertRecord {
	now := demoTimestamp()
	mk := func(fp, cluster, status, name, sev, summary, source string, agoMin int) store.AlertRecord {
		t := now.Add(-time.Duration(agoMin) * time.Minute)
		return store.AlertRecord{
			Fingerprint: fp,
			Cluster:     cluster,
			Status:      status,
			AlertName:   name,
			Severity:    sev,
			Summary:     summary,
			StartsAt:    t,
			ReceivedAt:  t,
			Labels:      map[string]string{"source": source, "cluster": cluster, "severity": sev},
		}
	}
	return []store.AlertRecord{
		mk("demo-al-1", "prod-us-east-1", "firing", "KubeMemoryPressure", "critical",
			"2 nodes have reported MemoryPressure for over 10 minutes.", "alertmanager", 8),
		mk("demo-al-2", "store-nyc-42", "firing", "UnexpectedOutboundConnection", "critical",
			"A container opened an outbound connection to a host outside the allowlist.", "falco", 15),
		mk("demo-al-3", "factory-osaka", "firing", "AdmissionWebhookDown", "critical",
			"ValidatingWebhook policy-engine/scc has no ready endpoints.", "alertmanager", 22),
		mk("demo-al-4", "prod-eu-central-1", "firing", "DeprecatedAPIInUse", "warning",
			"policy/v1beta1 PodDisruptionBudget is still in use before the next upgrade.", "alertmanager", 40),
		mk("demo-al-5", "store-london-soho", "firing", "WriteBelowEtc", "warning",
			"A container process wrote under /etc at runtime.", "falco", 55),
		mk("demo-al-6", "prod-us-west-2", "resolved", "HighCPUThrottling", "warning",
			"CPU throttling cleared after the cluster autoscaled.", "alertmanager", 90),
	}
}
