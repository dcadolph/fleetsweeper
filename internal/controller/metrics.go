package controller

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Atomic counters exported via WriteMetrics. The controller is package-scoped
// (one per process at most) so package-level atomics are appropriate. Tests
// reset them via ResetMetrics.
var (
	reconcileTotal atomic.Int64
	reconcileOK    atomic.Int64
	reconcileFail  atomic.Int64
	scansTriggered atomic.Int64
	scansSucceeded atomic.Int64
	scansFailed    atomic.Int64
	pausedSeen     atomic.Int64
)

// recordReconcile is called once per reconcile pass for one resource.
func recordReconcile() { reconcileTotal.Add(1) }

// recordReconcileOK is called when a reconcile pass completes without error.
func recordReconcileOK() { reconcileOK.Add(1) }

// recordReconcileFail is called when reconciliation hit a definitive error.
func recordReconcileFail() { reconcileFail.Add(1) }

// recordScanTriggered is called when the controller fires a scan.
func recordScanTriggered() { scansTriggered.Add(1) }

// recordScanResult is called when a controller-triggered scan completes.
func recordScanResult(success bool) {
	if success {
		scansSucceeded.Add(1)
		return
	}
	scansFailed.Add(1)
}

// recordPaused is called when a reconciliation pass found spec.paused=true.
func recordPaused() { pausedSeen.Add(1) }

// WriteMetrics emits the controller's counters in the Prometheus text
// exposition format. Safe to call from any goroutine; the server's
// /metrics handler calls this after its own output.
func WriteMetrics(w io.Writer) {
	fmt.Fprintln(w, "# HELP fleetsweeper_controller_reconcile_total Total reconcile passes the ClusterScan controller has performed.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_controller_reconcile_total counter")
	fmt.Fprintf(w, "fleetsweeper_controller_reconcile_total %d\n", reconcileTotal.Load())

	fmt.Fprintln(w, "# HELP fleetsweeper_controller_reconcile_outcome_total Reconcile passes broken out by outcome.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_controller_reconcile_outcome_total counter")
	fmt.Fprintf(w, `fleetsweeper_controller_reconcile_outcome_total{outcome="success"} %d`+"\n", reconcileOK.Load())
	fmt.Fprintf(w, `fleetsweeper_controller_reconcile_outcome_total{outcome="failure"} %d`+"\n", reconcileFail.Load())

	fmt.Fprintln(w, "# HELP fleetsweeper_controller_scans_total Scans the controller has triggered.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_controller_scans_total counter")
	fmt.Fprintf(w, `fleetsweeper_controller_scans_total{result="triggered"} %d`+"\n", scansTriggered.Load())
	fmt.Fprintf(w, `fleetsweeper_controller_scans_total{result="success"} %d`+"\n", scansSucceeded.Load())
	fmt.Fprintf(w, `fleetsweeper_controller_scans_total{result="failure"} %d`+"\n", scansFailed.Load())

	fmt.Fprintln(w, "# HELP fleetsweeper_controller_paused_resources Resources observed with spec.paused=true on the most recent reconcile cycle.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_controller_paused_resources counter")
	fmt.Fprintf(w, "fleetsweeper_controller_paused_resources %d\n", pausedSeen.Load())
}

// ResetMetrics zeroes every counter. Intended for tests only.
func ResetMetrics() {
	reconcileTotal.Store(0)
	reconcileOK.Store(0)
	reconcileFail.Store(0)
	scansTriggered.Store(0)
	scansSucceeded.Store(0)
	scansFailed.Store(0)
	pausedSeen.Store(0)
}
