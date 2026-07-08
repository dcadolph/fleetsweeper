package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// topCmd is an htop-style live view of the worst-N clusters in a fleet.
// Polls a running Fleetsweeper server on an interval and renders a sorted
// table. Useful for status TVs and operator triage.
var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Live, sorted view of fleet clusters by score",
	Long: "Connect to a running Fleetsweeper server and continuously render a " +
		"sorted table of clusters. Inspired by htop: q to quit, p to pause, s " +
		"to cycle sort order, r to refresh now.",
	RunE: runTop,
}

func init() {
	topCmd.Flags().String("server", "http://localhost:8080", "Fleetsweeper server URL.")
	topCmd.Flags().Duration("interval", 5*time.Second, "Refresh interval.")
	topCmd.Flags().Int("limit", 20, "How many clusters to display.")
	topCmd.Flags().Bool("no-color", false, "Disable ANSI colors (e.g. for logging).")
}

// runTop is the cobra entrypoint for the top subcommand.
func runTop(cmd *cobra.Command, _ []string) error {
	ctx := cmdContext(cmd)
	server, _ := cmd.Flags().GetString("server")
	interval, _ := cmd.Flags().GetDuration("interval")
	limit, _ := cmd.Flags().GetInt("limit")
	noColor, _ := cmd.Flags().GetBool("no-color")

	state := &topState{
		server:   strings.TrimRight(server, "/"),
		interval: interval,
		limit:    limit,
		color:    !noColor && term.IsTerminal(int(os.Stdout.Fd())),
		client:   &http.Client{Timeout: 6 * time.Second},
		out:      cmd.OutOrStdout(),
		sortBy:   sortByScore,
	}
	return state.run(ctx)
}

// topState holds the runtime for one `top` invocation.
type topState struct {
	server   string
	interval time.Duration
	limit    int
	color    bool
	client   *http.Client
	out      io.Writer
	// paused, when 1, stops the auto-refresh timer (manual r still works).
	paused atomic.Bool
	// sortBy cycles between three orderings via the 's' key.
	sortBy topSortMode
}

// topSortMode enumerates the cycle of sort orders.
type topSortMode int

const (
	sortByScore topSortMode = iota
	sortByName
	sortByStatus
)

// run drives the main loop until the context is canceled, the user presses
// q, or Stdin closes.
func (s *topState) run(ctx context.Context) error {
	isTTY := term.IsTerminal(int(os.Stdin.Fd()))
	var restore func() error
	if isTTY {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			restore = func() error { return term.Restore(int(os.Stdin.Fd()), oldState) }
			defer func() { _ = restore() }()
		}
	}

	keys := make(chan byte, 8)
	if isTTY {
		go readKeys(ctx, keys)
	}

	refresh := make(chan struct{}, 1)
	refresh <- struct{}{}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.clear()
			return nil
		case <-refresh:
			if err := s.draw(ctx); err != nil {
				s.printError(err)
			}
		case <-ticker.C:
			if s.paused.Load() {
				continue
			}
			select {
			case refresh <- struct{}{}:
			default:
			}
		case k := <-keys:
			switch k {
			case 'q', 'Q', 3 /* Ctrl-C */ :
				s.clear()
				return nil
			case 'p', 'P':
				s.paused.Store(!s.paused.Load())
				select {
				case refresh <- struct{}{}:
				default:
				}
			case 's', 'S':
				s.sortBy = (s.sortBy + 1) % 3
				select {
				case refresh <- struct{}{}:
				default:
				}
			case 'r', 'R':
				select {
				case refresh <- struct{}{}:
				default:
				}
			}
		}
	}
}

// readKeys forwards single bytes from stdin to ch until ctx is canceled.
func readKeys(ctx context.Context, ch chan<- byte) {
	buf := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		select {
		case ch <- buf[0]:
		case <-ctx.Done():
			return
		}
	}
}

// draw fetches the latest report from the server and renders the table.
func (s *topState) draw(ctx context.Context) error {
	rpt, prevRpt, err := s.fetchLatestReports(ctx)
	if err != nil {
		return err
	}
	rows := s.buildRows(rpt, prevRpt)
	sort.Slice(rows, s.lessFn(rows))
	if len(rows) > s.limit {
		rows = rows[:s.limit]
	}

	s.clear()
	s.printHeader(rpt, prevRpt)
	s.printTable(rows)
	s.printFooter()
	return nil
}

// topRow is one cluster's worth of data for the table.
type topRow struct {
	Cluster  string
	Status   string
	Score    int
	CPU      float64
	Memory   float64
	Critical int
	Warning  int
	Delta    int
}

// buildRows converts the latest report into table rows, computing per-cluster
// score deltas against the previous report when available.
func (s *topState) buildRows(rpt, prev *topReport) []topRow {
	prevByName := map[string]int{}
	if prev != nil {
		for _, c := range prev.ClusterScores {
			prevByName[c.Cluster] = c.Score
		}
	}
	out := make([]topRow, 0, len(rpt.ClusterHealths))
	scoresByCluster := map[string]int{}
	for _, c := range rpt.ClusterScores {
		scoresByCluster[c.Cluster] = c.Score
	}
	for _, h := range rpt.ClusterHealths {
		score := scoresByCluster[h.Name]
		critical, warning := 0, 0
		for _, f := range rpt.Findings {
			if f.Cluster != h.Name {
				continue
			}
			switch f.Severity {
			case "critical":
				critical++
			case "warning":
				warning++
			}
		}
		out = append(out, topRow{
			Cluster:  h.Name,
			Status:   h.Status,
			Score:    score,
			CPU:      h.AvgCPU,
			Memory:   h.AvgMemory,
			Critical: critical,
			Warning:  warning,
			Delta:    score - prevByName[h.Name],
		})
	}
	return out
}

// lessFn returns a sort comparator based on the current sort mode.
func (s *topState) lessFn(rows []topRow) func(i, j int) bool {
	switch s.sortBy {
	case sortByName:
		return func(i, j int) bool { return rows[i].Cluster < rows[j].Cluster }
	case sortByStatus:
		order := map[string]int{"critical": 0, "degraded": 1, "busy": 2, "healthy": 3}
		return func(i, j int) bool {
			if order[rows[i].Status] != order[rows[j].Status] {
				return order[rows[i].Status] < order[rows[j].Status]
			}
			return rows[i].Score < rows[j].Score
		}
	default:
		return func(i, j int) bool { return rows[i].Score < rows[j].Score }
	}
}

// topReport is the subset of the server's report shape we need for the TUI.
type topReport struct {
	Timestamp      string             `json:"timestamp"`
	Clusters       []string           `json:"clusters"`
	FleetScore     topFleetScore      `json:"fleet_score"`
	ClusterHealths []topClusterHealth `json:"cluster_healths"`
	Findings       []topFinding       `json:"findings"`
	// ClusterScores is populated by buildRows by calling /api/forecast/clusters
	// (which gives us per-cluster scores). When that endpoint is unavailable we
	// fall back to a synthetic score derived from health.
	ClusterScores []topClusterScore `json:"-"`
}

// topFleetScore mirrors the wire shape.
type topFleetScore struct {
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

// topClusterHealth mirrors the wire shape.
type topClusterHealth struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	AvgCPU    float64 `json:"avg_cpu"`
	AvgMemory float64 `json:"avg_memory"`
}

// topFinding mirrors the wire shape.
type topFinding struct {
	Severity string `json:"severity"`
	Cluster  string `json:"cluster"`
}

// topClusterScore mirrors the per-cluster forecast response.
type topClusterScore struct {
	Cluster string `json:"cluster"`
	Score   int    `json:"score"`
}

// fetchLatestReports returns the latest report and (optionally) the previous
// one for delta computation.
func (s *topState) fetchLatestReports(ctx context.Context) (*topReport, *topReport, error) {
	var scans []struct {
		ID string `json:"id"`
	}
	if err := s.getJSON(ctx, "/api/scans?limit=2", &scans); err != nil {
		return nil, nil, err
	}
	if len(scans) == 0 {
		return nil, nil, fmt.Errorf("no scans available")
	}
	cur := &topReport{}
	if err := s.getJSON(ctx, "/api/scans/"+scans[0].ID+"/report", cur); err != nil {
		return nil, nil, err
	}
	s.hydrateScores(ctx, cur)

	var prev *topReport
	if len(scans) > 1 {
		p := &topReport{}
		if err := s.getJSON(ctx, "/api/scans/"+scans[1].ID+"/report", p); err == nil {
			s.hydrateScores(ctx, p)
			prev = p
		}
	}
	return cur, prev, nil
}

// hydrateScores fills in per-cluster scores. Prefers the forecast endpoint
// (which has per-cluster scores already computed); falls back to synthesizing
// from cluster status when that endpoint is missing.
func (s *topState) hydrateScores(ctx context.Context, r *topReport) {
	var resp struct {
		Forecasts []struct {
			Cluster      string `json:"cluster"`
			CurrentScore int    `json:"current_score"`
		} `json:"forecasts"`
	}
	if err := s.getJSON(ctx, "/api/forecast/clusters", &resp); err == nil && len(resp.Forecasts) > 0 {
		for _, f := range resp.Forecasts {
			r.ClusterScores = append(r.ClusterScores,
				topClusterScore{Cluster: f.Cluster, Score: f.CurrentScore})
		}
		return
	}
	for _, h := range r.ClusterHealths {
		score := 100
		switch h.Status {
		case "critical":
			score = 40
		case "degraded":
			score = 75
		case "busy":
			score = 90
		}
		r.ClusterScores = append(r.ClusterScores,
			topClusterScore{Cluster: h.Name, Score: score})
	}
}

// getJSON GETs the URL and decodes into out.
func (s *topState) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.server+path, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// clear emits ANSI codes to clear the screen and move the cursor home.
func (s *topState) clear() {
	if !s.color {
		fmt.Fprint(s.out, "\n\n")
		return
	}
	fmt.Fprint(s.out, "\033[H\033[2J")
}

// printHeader renders the title line and the fleet-score summary.
func (s *topState) printHeader(rpt, prev *topReport) {
	pausedNote := ""
	if s.paused.Load() {
		pausedNote = "  [PAUSED]"
	}
	fmt.Fprintf(s.out, "fleetsweeper top  -  %s%s\r\n", s.server, pausedNote)
	delta := ""
	if prev != nil && prev.FleetScore.Score != 0 {
		d := rpt.FleetScore.Score - prev.FleetScore.Score
		sign := ""
		if d > 0 {
			sign = "+"
		}
		delta = fmt.Sprintf("  (%s%d vs previous)", sign, d)
	}
	fmt.Fprintf(s.out, "Fleet Score: %s%d (%s)%s%s  %d clusters  sorted by %s\r\n",
		s.color3(s.fleetColor(rpt.FleetScore.Score)),
		rpt.FleetScore.Score, rpt.FleetScore.Grade, s.resetCode(),
		delta, len(rpt.Clusters), s.sortLabel())
	fmt.Fprintln(s.out)
}

// printTable writes the per-cluster table.
func (s *topState) printTable(rows []topRow) {
	header := fmt.Sprintf("%-28s  %-9s  %5s  %5s  %5s  %4s  %4s  %5s",
		"CLUSTER", "STATUS", "SCORE", "CPU%", "MEM%", "CRIT", "WARN", "DELTA")
	fmt.Fprintf(s.out, "%s%s%s\r\n", s.dim(), header, s.resetCode())
	for _, r := range rows {
		statusColor := statusColor(r.Status)
		scoreColor := scoreColorCode(r.Score)
		fmt.Fprintf(s.out, "%-28s  %s%-9s%s  %s%5d%s  %5.1f  %5.1f  %4d  %4d  %s%5s%s\r\n",
			truncR(r.Cluster, 28),
			s.color3(statusColor), r.Status, s.resetCode(),
			s.color3(scoreColor), r.Score, s.resetCode(),
			r.CPU, r.Memory, r.Critical, r.Warning,
			s.color3(deltaColor(r.Delta)), formatDelta(r.Delta), s.resetCode())
	}
}

// printFooter renders the key-binding row.
func (s *topState) printFooter() {
	fmt.Fprintln(s.out)
	fmt.Fprintf(s.out, "%s[q] quit  [p] pause  [s] sort  [r] refresh%s\r\n",
		s.dim(), s.resetCode())
}

// printError writes a one-line error in place of the table.
func (s *topState) printError(err error) {
	s.clear()
	fmt.Fprintf(s.out, "fleetsweeper top: %s\r\n", err)
}

// sortLabel returns the human-readable label for the active sort mode.
func (s *topState) sortLabel() string {
	switch s.sortBy {
	case sortByName:
		return "name"
	case sortByStatus:
		return "status"
	default:
		return "score (worst first)"
	}
}

// fleetColor maps a fleet score to a color code.
func (s *topState) fleetColor(score int) string {
	switch {
	case score >= 80:
		return "32"
	case score >= 60:
		return "33"
	default:
		return "31"
	}
}

// color3 returns the ANSI escape for the color code, or empty when color is off.
func (s *topState) color3(code string) string {
	if !s.color {
		return ""
	}
	return "\033[" + code + "m"
}

// resetCode returns the ANSI reset sequence when color is enabled.
func (s *topState) resetCode() string {
	if !s.color {
		return ""
	}
	return "\033[0m"
}

// dim returns the ANSI dim sequence when color is enabled.
func (s *topState) dim() string {
	if !s.color {
		return ""
	}
	return "\033[90m"
}

// statusColor returns an ANSI color code for the cluster status string.
func statusColor(status string) string {
	switch status {
	case "critical":
		return "31"
	case "degraded", "strained":
		return "33"
	case "busy":
		return "34"
	default:
		return "32"
	}
}

// scoreColorCode returns an ANSI code based on the 0-100 score.
func scoreColorCode(score int) string {
	switch {
	case score >= 80:
		return "32"
	case score >= 60:
		return "33"
	default:
		return "31"
	}
}

// deltaColor returns an ANSI code based on the per-cluster delta. Improving
// (positive) is green; degrading (negative) is red.
func deltaColor(d int) string {
	switch {
	case d > 0:
		return "32"
	case d < 0:
		return "31"
	default:
		return "90"
	}
}

// formatDelta renders an integer delta with a leading sign and triangle.
func formatDelta(d int) string {
	switch {
	case d > 0:
		return fmt.Sprintf("+%d", d)
	case d < 0:
		return fmt.Sprintf("%d", d)
	default:
		return "0"
	}
}

// truncR right-pads or truncates s to width characters.
func truncR(s string, width int) string {
	if len(s) > width {
		return s[:width-1] + "…"
	}
	return s
}
