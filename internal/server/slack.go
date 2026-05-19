package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// slackNotifyTimeout is the per-request HTTP timeout for posting to a Slack
// incoming webhook. Slack's own SLO is well under this; the timeout exists to
// keep a misbehaving webhook from wedging a scan goroutine.
const slackNotifyTimeout = 8 * time.Second

// slackDedupTTL is how long a finding fingerprint counts as "already
// notified" before a repeat would re-fire. Set so that a scan running every
// 30 minutes does not spam the channel about long-standing criticals.
const slackDedupTTL = 6 * time.Hour

// slackMaxFindingsPerPost caps how many critical findings appear in a single
// Slack message body. The remainder is summarised inline so the message stays
// readable.
const slackMaxFindingsPerPost = 8

// notifySlackForReport posts new critical findings from the rebuilt report to
// the configured Slack webhook. Returns silently if no webhook is configured,
// if there are no critical findings, or if every critical has been notified
// recently. Errors are logged but never returned to the caller, because
// notification failure must never break a scan.
func (s *Server) notifySlackForReport(ctx context.Context, r *report.Report) {
	if s.slackWebhookURL == "" || r == nil {
		return
	}
	criticals := filterCriticals(r.Findings)
	criticals = s.filterAckedFindings(ctx, criticals)
	if len(criticals) == 0 {
		return
	}
	fresh := s.dedupCriticals(criticals)
	if len(fresh) == 0 {
		return
	}

	payload := buildSlackPayload(fresh, r)
	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Warn("slack: marshal payload", zap.Error(err))
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, slackNotifyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.slackWebhookURL,
		bytes.NewReader(body))
	if err != nil {
		s.log.Warn("slack: build request", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.log.Warn("slack: post failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.log.Warn("slack: non-2xx response", zap.Int("status", resp.StatusCode))
		return
	}
	s.log.Info("slack: notified", zap.Int("findings", len(fresh)))
}

// filterCriticals returns only the critical findings from a finding list.
func filterCriticals(findings []report.Finding) []report.Finding {
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == report.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}

// filterAckedFindings drops findings whose fingerprint matches an active
// acknowledgement in the store. Acked findings are intentionally not
// notified again until the operator clears or snooze expires. Safe when
// the server has no store (tests construct stripped-down Server values).
func (s *Server) filterAckedFindings(ctx context.Context, findings []report.Finding) []report.Finding {
	if len(findings) == 0 || s.store == nil {
		return findings
	}
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		fp := storeAckFingerprint(f.Cluster, f.Scanner, f.Title)
		acked, _ := s.store.IsAcked(ctx, fp)
		if acked {
			continue
		}
		out = append(out, f)
	}
	return out
}

// dedupCriticals removes findings whose fingerprint has been notified within
// slackDedupTTL, then records the survivors as notified. The dedupe state
// lives on the server so a restart cleanly re-notifies operators about
// outstanding criticals (intentional: a restart is a good time to confirm
// state is still bad).
func (s *Server) dedupCriticals(findings []report.Finding) []report.Finding {
	s.slackMu.Lock()
	defer s.slackMu.Unlock()
	now := time.Now()

	// Prune stale entries first so the map cannot grow unbounded.
	for k, t := range s.slackNotifiedKeys {
		if now.Sub(t) > slackDedupTTL {
			delete(s.slackNotifiedKeys, k)
		}
	}

	var fresh []report.Finding
	for _, f := range findings {
		key := findingFingerprint(f)
		if _, seen := s.slackNotifiedKeys[key]; seen {
			continue
		}
		fresh = append(fresh, f)
		s.slackNotifiedKeys[key] = now
	}
	return fresh
}

// findingFingerprint returns a stable hash of a finding's identifying fields
// (cluster, scanner, title). Two scans that surface the same condition share
// a fingerprint and therefore only notify once per dedup window.
func findingFingerprint(f report.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.Cluster))
	h.Write([]byte{0})
	h.Write([]byte(f.Scanner))
	h.Write([]byte{0})
	h.Write([]byte(f.Title))
	return hex.EncodeToString(h.Sum(nil))
}

// slackPayload is the minimal Slack incoming-webhook body. We use the
// blocks API so the message renders with structure rather than as a wall of
// text, but keep the JSON shape narrow so a future change to a richer
// notification need not migrate a large struct.
type slackPayload struct {
	// Text is the fallback text shown in notifications and previews.
	Text string `json:"text"`
	// Blocks is the structured message body rendered in the Slack client.
	Blocks []slackBlock `json:"blocks,omitempty"`
}

// slackBlock is a single Slack Block Kit block. Only the fields we use are
// modelled; Slack tolerates unknown keys gracefully.
type slackBlock struct {
	// Type is the block type, for example "header", "section", "divider".
	Type string `json:"type"`
	// Text is the text body for header and section blocks.
	Text *slackText `json:"text,omitempty"`
	// Fields renders a two-column key-value grid in a section block.
	Fields []*slackText `json:"fields,omitempty"`
}

// slackText is a Slack Block Kit text object.
type slackText struct {
	// Type is "plain_text" or "mrkdwn".
	Type string `json:"type"`
	// Text is the body content.
	Text string `json:"text"`
}

// buildSlackPayload composes the Block Kit message for the given fresh
// critical findings drawn from the latest report.
func buildSlackPayload(fresh []report.Finding, r *report.Report) slackPayload {
	header := fmt.Sprintf("Fleetsweeper: %d new critical finding%s",
		len(fresh), plural(len(fresh)))
	score := ""
	if r != nil {
		score = fmt.Sprintf("Fleet Score: %d/%s ; %d cluster%s scanned.",
			r.FleetScore.Score, r.FleetScore.Grade,
			len(r.Clusters), plural(len(r.Clusters)))
	}

	blocks := []slackBlock{
		{Type: "header", Text: &slackText{Type: "plain_text", Text: header}},
	}
	if score != "" {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: score},
		})
	}
	blocks = append(blocks, slackBlock{Type: "divider"})

	limit := len(fresh)
	if limit > slackMaxFindingsPerPost {
		limit = slackMaxFindingsPerPost
	}
	for _, f := range fresh[:limit] {
		blocks = append(blocks, findingBlock(f))
	}
	if len(fresh) > slackMaxFindingsPerPost {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("_+ %d more not shown_", len(fresh)-slackMaxFindingsPerPost),
			},
		})
	}
	return slackPayload{Text: header, Blocks: blocks}
}

// findingBlock renders one finding as a Slack section block: title in bold,
// cluster + scanner in fields, and the kubectl remediation in a fenced code
// block when present.
func findingBlock(f report.Finding) slackBlock {
	body := "*" + slackEscape(f.Title) + "*"
	if f.Description != "" {
		body += "\n" + slackEscape(truncate(f.Description, 280))
	}
	if f.Remediation != nil && f.Remediation.Command != "" {
		body += "\n```" + f.Remediation.Command + "```"
	}
	cluster := f.Cluster
	if cluster == "" {
		cluster = "fleet"
	}
	return slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: body},
		Fields: []*slackText{
			{Type: "mrkdwn", Text: "*Cluster*\n" + slackEscape(cluster)},
			{Type: "mrkdwn", Text: "*Scanner*\n" + slackEscape(f.Scanner)},
		},
	}
}

// slackEscape escapes the three characters Slack's mrkdwn dialect treats as
// active and that we never want to render literally inside a finding.
func slackEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// plural is the package-level singular/plural suffix helper, re-exposed here
// so slack.go does not have to import the report package's private helper.
// We deliberately duplicate the four-line helper rather than create a util
// package for one function.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
