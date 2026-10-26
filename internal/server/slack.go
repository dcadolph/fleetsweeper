package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
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
// Slack message body. The remainder is summarized inline so the message stays
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
		fp := report.FindingFingerprint(f)
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
		key := report.FindingFingerprint(f)
		if _, seen := s.slackNotifiedKeys[key]; seen {
			continue
		}
		fresh = append(fresh, f)
		s.slackNotifiedKeys[key] = now
	}
	return fresh
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
// modeled; Slack tolerates unknown keys gracefully.
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
		len(fresh), util.Plural(len(fresh)))
	score := ""
	if r != nil {
		score = fmt.Sprintf("Fleet Score: %d/%s ; scored from %d cluster%s across %d dimension%s.",
			r.FleetScore.Score, r.FleetScore.Grade,
			r.FleetScore.SampleSize, util.Plural(r.FleetScore.SampleSize),
			r.FleetScore.Dimensions, util.Plural(r.FleetScore.Dimensions))
		if r.FleetScore.ExcludedClusters > 0 {
			score += fmt.Sprintf(" %d cluster%s excluded for insufficient data.",
				r.FleetScore.ExcludedClusters, util.Plural(r.FleetScore.ExcludedClusters))
		}
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

	limit := min(len(fresh), slackMaxFindingsPerPost)
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
		body += "\n" + slackEscape(util.Truncate(f.Description, 280))
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
