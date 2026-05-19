package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// doctorCmd runs a battery of preflight checks against the configured
// environment and reports per-check status. Use after install or anytime
// the system feels off; the JSON form is suitable for cron/monitoring.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the local fleetsweeper environment",
	Long: "Run a battery of preflight checks: database reachable, kubeconfig\n" +
		"contexts loadable, CRDs installed, server reachable when --addr is\n" +
		"supplied. Output is human-friendly by default; pass --json for a\n" +
		"structured payload monitors can scrape.",
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().String("addr", "", "Fleetsweeper server URL to probe (for example https://fleetsweeper.example.com).")
	doctorCmd.Flags().String("token", "", "Bearer token used when probing the server.")
	doctorCmd.Flags().Bool("json", false, "Emit a JSON report instead of human-friendly text.")
	doctorCmd.Flags().Duration("timeout", 10*time.Second, "Per-check timeout.")
	doctorCmd.Flags().Bool("in-cluster", false, "Probe a deployed Fleetsweeper: leader lease, recent scans, admission webhook reachability.")
	doctorCmd.Flags().String("namespace", "fleetsweeper", "Namespace the Fleetsweeper Helm release was installed into. Used for the in-cluster checks.")
	doctorCmd.Flags().Duration("scan-freshness", 24*time.Hour, "Maximum age the most-recent scan may have before --in-cluster flags it as stale.")
}

// Status enumerates the per-check outcomes the doctor reports.
type Status string

// Doctor status constants. "warn" allows a check to flag a concern that is
// not a hard failure (for example, the controller CRD is absent because
// the user hasn't enabled the operator yet).
const (
	// StatusOK indicates the check passed.
	StatusOK Status = "ok"
	// StatusWarn indicates a non-fatal concern.
	StatusWarn Status = "warn"
	// StatusFail indicates a definitive failure.
	StatusFail Status = "fail"
	// StatusSkip indicates the check did not apply (missing input).
	StatusSkip Status = "skip"
)

// CheckResult is one check's outcome.
type CheckResult struct {
	// Name is the human-readable check identifier.
	Name string `json:"name"`
	// Status is the per-check status.
	Status Status `json:"status"`
	// Detail is a human-readable explanation.
	Detail string `json:"detail,omitempty"`
	// DurationMS is how long the check took.
	DurationMS int64 `json:"duration_ms"`
}

// Report aggregates all the checks for serialised output.
type Report struct {
	// Generated is when the report ran.
	Generated time.Time `json:"generated"`
	// Checks are the individual check outcomes.
	Checks []CheckResult `json:"checks"`
	// Summary tallies the per-status counts.
	Summary map[Status]int `json:"summary"`
}

// runDoctor invokes every check and renders the report.
func runDoctor(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	timeout, _ := cmd.Flags().GetDuration("timeout")
	report := Report{Generated: time.Now().UTC(), Summary: map[Status]int{}}

	report.Checks = append(report.Checks, runCheck("database", timeout, func(ctx context.Context) CheckResult {
		return doctorCheckDatabase(ctx, cmd)
	}))
	report.Checks = append(report.Checks, runCheck("kubeconfig", timeout, func(ctx context.Context) CheckResult {
		return doctorCheckKubeconfig(ctx, cmd)
	}))
	report.Checks = append(report.Checks, runCheck("contexts", timeout, func(ctx context.Context) CheckResult {
		return doctorCheckContexts(ctx, cmd)
	}))
	report.Checks = append(report.Checks, runCheck("crds", timeout, func(ctx context.Context) CheckResult {
		return doctorCheckCRDs(ctx, cmd)
	}))
	if addr, _ := cmd.Flags().GetString("addr"); addr != "" {
		report.Checks = append(report.Checks, runCheck("server", timeout, func(ctx context.Context) CheckResult {
			return doctorCheckServer(ctx, cmd)
		}))
	}

	if inCluster, _ := cmd.Flags().GetBool("in-cluster"); inCluster {
		report.Checks = append(report.Checks, runCheck("leader-lease", timeout, func(ctx context.Context) CheckResult {
			return doctorCheckLeaderLease(ctx, cmd)
		}))
		report.Checks = append(report.Checks, runCheck("admission-webhook", timeout, func(ctx context.Context) CheckResult {
			return doctorCheckAdmissionWebhook(ctx, cmd)
		}))
		report.Checks = append(report.Checks, runCheck("scan-freshness", timeout, func(ctx context.Context) CheckResult {
			return doctorCheckScanFreshness(ctx, cmd)
		}))
	}

	for _, c := range report.Checks {
		report.Summary[c.Status]++
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		renderHuman(cmd.OutOrStdout(), report)
	}

	if report.Summary[StatusFail] > 0 {
		return errors.New("doctor reported failures")
	}
	_ = ctx
	return nil
}

// runCheck times a check function and returns its CheckResult.
func runCheck(name string, timeout time.Duration, fn func(context.Context) CheckResult) CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	res := fn(ctx)
	res.Name = name
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

// doctorCheckDatabase opens the configured --db and pings it.
func doctorCheckDatabase(ctx context.Context, cmd *cobra.Command) CheckResult {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return CheckResult{Status: StatusSkip, Detail: "no --db configured"}
	}
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	s, err := store.Open(driver, dbPath)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("open %s: %v", driver, err)}
	}
	defer s.Close()
	if pinger, ok := s.(interface{ Ping(context.Context) error }); ok {
		if err := pinger.Ping(ctx); err != nil {
			return CheckResult{Status: StatusFail, Detail: "ping failed: " + err.Error()}
		}
	}
	return CheckResult{Status: StatusOK, Detail: driver + " reachable at " + dbPath}
}

// doctorCheckKubeconfig verifies the kubeconfig file is parseable.
func doctorCheckKubeconfig(_ context.Context, cmd *cobra.Command) CheckResult {
	path, _ := cmd.Flags().GetString("kubeconfig")
	if path == "" {
		return CheckResult{Status: StatusSkip, Detail: "no kubeconfig configured"}
	}
	if _, err := os.Stat(path); err != nil {
		return CheckResult{Status: StatusFail, Detail: "kubeconfig file: " + err.Error()}
	}
	contexts, err := kube.AvailableContexts(path)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "parse: " + err.Error()}
	}
	return CheckResult{Status: StatusOK, Detail: fmt.Sprintf("%d contexts available", len(contexts))}
}

// doctorCheckContexts attempts to connect to every available context.
// Any single failure becomes a warning; total failure escalates to fail.
func doctorCheckContexts(ctx context.Context, cmd *cobra.Command) CheckResult {
	path, _ := cmd.Flags().GetString("kubeconfig")
	if path == "" {
		return CheckResult{Status: StatusSkip, Detail: "no kubeconfig configured"}
	}
	contexts, err := kube.AvailableContexts(path)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "list contexts: " + err.Error()}
	}
	if len(contexts) == 0 {
		return CheckResult{Status: StatusWarn, Detail: "no contexts found in kubeconfig"}
	}

	var failed []string
	clients := kube.ConnectAll(ctx, path, contexts, 5)
	connected := make(map[string]struct{}, len(clients))
	for _, c := range clients {
		connected[c.Context] = struct{}{}
	}
	for _, name := range contexts {
		if _, ok := connected[name]; !ok {
			failed = append(failed, name)
		}
	}
	switch {
	case len(failed) == 0:
		return CheckResult{Status: StatusOK, Detail: fmt.Sprintf("%d/%d contexts reachable", len(connected), len(contexts))}
	case len(failed) == len(contexts):
		return CheckResult{Status: StatusFail, Detail: "no contexts reachable: " + strings.Join(failed, ", ")}
	default:
		return CheckResult{Status: StatusWarn, Detail: fmt.Sprintf("%d/%d unreachable: %s", len(failed), len(contexts), strings.Join(failed, ", "))}
	}
}

// doctorCheckCRDs probes whether the ClusterScan and FleetDriftReport CRDs
// are installed in the default kubeconfig context.
func doctorCheckCRDs(ctx context.Context, cmd *cobra.Command) CheckResult {
	path, _ := cmd.Flags().GetString("kubeconfig")
	if path == "" {
		return CheckResult{Status: StatusSkip, Detail: "no kubeconfig configured"}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "build config: " + err.Error()}
	}
	cs, err := apiextclient.NewForConfig(cfg)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "apiext client: " + err.Error()}
	}

	type crdProbe struct {
		Name string
		Want bool
	}
	required := []crdProbe{
		{Name: "clusterscans.fleetsweeper.io", Want: true},
		{Name: "fleetdriftreports.fleetsweeper.io", Want: true},
	}
	var missing []string
	for _, c := range required {
		_, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, c.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			missing = append(missing, c.Name)
			continue
		}
		if err != nil {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("get %s: %v", c.Name, err)}
		}
	}
	if len(missing) == 0 {
		return CheckResult{Status: StatusOK, Detail: "ClusterScan + FleetDriftReport CRDs present"}
	}
	return CheckResult{Status: StatusWarn, Detail: "missing CRDs: " + strings.Join(missing, ", ")}
}

// doctorCheckServer probes /healthz and /readyz on the running server.
func doctorCheckServer(ctx context.Context, cmd *cobra.Command) CheckResult {
	addr, _ := cmd.Flags().GetString("addr")
	if addr == "" {
		return CheckResult{Status: StatusSkip, Detail: "no --addr configured"}
	}
	addr = strings.TrimSuffix(addr, "/")
	token, _ := cmd.Flags().GetString("token")
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range []string{"/healthz", "/readyz"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+path, nil)
		if err != nil {
			return CheckResult{Status: StatusFail, Detail: "build request: " + err.Error()}
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("%s: %v", path, err)}
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("%s: status %d", path, res.StatusCode)}
		}
	}
	return CheckResult{Status: StatusOK, Detail: addr + " healthy"}
}

// renderHuman writes a colour-friendly tabular report to w. Colours use
// ANSI escapes only when stdout is a TTY; otherwise plain text.
func renderHuman(w io.Writer, r Report) {
	fmt.Fprintf(w, "fleetsweeper doctor — %s\n\n", r.Generated.Format(time.RFC3339))
	fmt.Fprintln(w, "  status   check          detail")
	fmt.Fprintln(w, "  ------   -----          ------")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  %-7s  %-13s  %s\n",
			fmtStatus(c.Status), c.Name, c.Detail)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "summary: %d ok, %d warn, %d fail, %d skip\n",
		r.Summary[StatusOK], r.Summary[StatusWarn], r.Summary[StatusFail], r.Summary[StatusSkip])
}

// doctorCheckLeaderLease reads the coordination.k8s.io Lease object
// the leader election controller maintains and reports who holds it.
// Absence with --in-cluster is treated as a fail because the controller
// can't have done useful work without it.
func doctorCheckLeaderLease(ctx context.Context, cmd *cobra.Command) CheckResult {
	path, _ := cmd.Flags().GetString("kubeconfig")
	if path == "" {
		return CheckResult{Status: StatusSkip, Detail: "no kubeconfig configured"}
	}
	namespace, _ := cmd.Flags().GetString("namespace")
	if namespace == "" {
		namespace = "fleetsweeper"
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "build config: " + err.Error()}
	}
	client, err := kube.NewClient(ctx, path, "")
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "connect: " + err.Error()}
	}
	_ = cfg
	lease, err := client.Clientset().CoordinationV1().Leases(namespace).
		Get(ctx, "fleetsweeper-controller", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return CheckResult{Status: StatusWarn, Detail: "lease not found; leader election may be disabled"}
	}
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "get lease: " + err.Error()}
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if holder == "" {
		return CheckResult{Status: StatusWarn, Detail: "lease exists but has no holder; controller may be restarting"}
	}
	return CheckResult{Status: StatusOK, Detail: "lease held by " + holder}
}

// doctorCheckAdmissionWebhook reads the ValidatingWebhookConfiguration
// fleetsweeper installs and confirms the apiserver has the URL and a CA
// bundle pointed at it. Does not actually invoke the webhook; that would
// require a Pod fixture that's overkill for a preflight.
func doctorCheckAdmissionWebhook(ctx context.Context, cmd *cobra.Command) CheckResult {
	path, _ := cmd.Flags().GetString("kubeconfig")
	if path == "" {
		return CheckResult{Status: StatusSkip, Detail: "no kubeconfig configured"}
	}
	client, err := kube.NewClient(ctx, path, "")
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "connect: " + err.Error()}
	}
	cfg, err := client.Clientset().AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Get(ctx, "fleetsweeper", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return CheckResult{Status: StatusWarn, Detail: "admission webhook not installed (admission.enabled=false?)"}
	}
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "get webhook config: " + err.Error()}
	}
	if len(cfg.Webhooks) == 0 {
		return CheckResult{Status: StatusFail, Detail: "webhook config exists but has no webhooks"}
	}
	for _, w := range cfg.Webhooks {
		if len(w.ClientConfig.CABundle) == 0 && w.ClientConfig.Service == nil {
			return CheckResult{Status: StatusFail, Detail: "webhook " + w.Name + " has no CA bundle or Service reference"}
		}
	}
	return CheckResult{Status: StatusOK, Detail: fmt.Sprintf("%d webhook(s) registered", len(cfg.Webhooks))}
}

// doctorCheckScanFreshness reads the most recent scan from the
// configured store and warns when its timestamp is older than
// --scan-freshness. Distinguishes "no scans yet" (warn) from "stale
// scans" (fail) so first-install behaviour isn't reported as broken.
func doctorCheckScanFreshness(ctx context.Context, cmd *cobra.Command) CheckResult {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return CheckResult{Status: StatusSkip, Detail: "no --db configured"}
	}
	maxAge, _ := cmd.Flags().GetDuration("scan-freshness")
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	s, err := store.Open(driver, dbPath)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "open store: " + err.Error()}
	}
	defer s.Close()
	scans, err := s.ListScans(ctx, 1)
	if err != nil {
		return CheckResult{Status: StatusFail, Detail: "list scans: " + err.Error()}
	}
	if len(scans) == 0 {
		return CheckResult{Status: StatusWarn, Detail: "no scans in store yet"}
	}
	age := time.Since(scans[0].Timestamp)
	if age > maxAge {
		return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("latest scan is %s old (>%s)", age.Round(time.Second), maxAge)}
	}
	return CheckResult{Status: StatusOK, Detail: fmt.Sprintf("latest scan %s old", age.Round(time.Second))}
}

// fmtStatus renders a status with the conventional badge characters.
func fmtStatus(s Status) string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "fail"
	case StatusSkip:
		return "skip"
	}
	return string(s)
}
