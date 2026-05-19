// Package remediate turns a Fleetsweeper finding with an inline YAML
// remediation into a pull request against a GitOps repository. The
// generated PR adds (or updates) a single manifest file at a stable path
// and links the finding's title and remediation hint in the description.
//
// This is the only Fleetsweeper code path that writes outside the local
// filesystem. It is deliberately opt-in: callers must explicitly invoke
// Open with WithPush(true). Without that flag the function returns the
// planned change without contacting GitHub.
package remediate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// defaultBaseURL is the GitHub REST API endpoint. Overridable for tests.
const defaultBaseURL = "https://api.github.com"

// requestTimeout caps a single GitHub API call. PRs are normally fast; a
// hard upper bound keeps a wedged API from hanging the CLI.
const requestTimeout = 15 * time.Second

// Options configures a single remediation PR.
type Options struct {
	// Owner is the GitHub org or user that owns the GitOps repo.
	Owner string
	// Repo is the GitHub repository name.
	Repo string
	// Finding is the finding to act on; must carry a non-empty YAML remediation.
	Finding report.Finding
	// Cluster is the cluster the remediation targets.
	Cluster string
	// Token is the GitHub personal access token or app token with repo write.
	Token string
	// BaseBranch overrides the default branch detected from the repo. Empty
	// means "use whatever the repo reports as its default".
	BaseBranch string
	// HeadBranch is the new branch name to create. When empty a slug derived
	// from the finding title is used.
	HeadBranch string
	// TargetPath is the path inside the repo where the manifest is written.
	// When empty the path defaults to "fleetsweeper/<cluster>/<slug>.yaml".
	TargetPath string
	// Push controls whether to actually call GitHub. When false the function
	// returns the planned change for review without touching the network.
	Push bool
	// BaseURL overrides the GitHub API endpoint. Used by tests; leave empty
	// in production.
	BaseURL string
	// HTTPClient overrides the default HTTP client. Used by tests.
	HTTPClient *http.Client
}

// Result describes a planned or executed remediation.
type Result struct {
	// PRURL is the URL of the created pull request. Empty when Push is false.
	PRURL string `json:"pr_url,omitempty"`
	// PRNumber is the pull request number. Zero when Push is false.
	PRNumber int `json:"pr_number,omitempty"`
	// HeadBranch is the branch that holds the change.
	HeadBranch string `json:"head_branch"`
	// BaseBranch is the branch the PR targets.
	BaseBranch string `json:"base_branch"`
	// TargetPath is the in-repo path of the manifest.
	TargetPath string `json:"target_path"`
	// PlannedYAML is the manifest body that was (or would have been) written.
	PlannedYAML string `json:"planned_yaml"`
	// PRTitle is the pull request title.
	PRTitle string `json:"pr_title"`
	// PRBody is the pull request body, rendered as Markdown.
	PRBody string `json:"pr_body"`
	// DryRun is true when Push was false; nothing was written.
	DryRun bool `json:"dry_run"`
}

// ErrNoYAML is returned when the finding has no inline YAML remediation to push.
var ErrNoYAML = errors.New("remediate: finding has no inline YAML remediation; nothing to push")

// Open prepares and (optionally) submits a remediation PR. Returns ErrNoYAML
// when the finding has no inline manifest to apply.
func Open(ctx context.Context, opts Options) (Result, error) {
	if opts.Finding.Remediation == nil || strings.TrimSpace(opts.Finding.Remediation.YAML) == "" {
		return Result{}, ErrNoYAML
	}
	if opts.Owner == "" || opts.Repo == "" {
		return Result{}, errors.New("remediate: --owner and --repo are required")
	}
	slug := slugify(opts.Finding.Title)
	if opts.HeadBranch == "" {
		opts.HeadBranch = "fleetsweeper/" + slug + "-" + time.Now().UTC().Format("20060102-150405")
	}
	if opts.TargetPath == "" {
		clusterSlug := slugify(opts.Cluster)
		if clusterSlug == "" {
			clusterSlug = "fleet"
		}
		opts.TargetPath = "fleetsweeper/" + clusterSlug + "/" + slug + ".yaml"
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: requestTimeout}
	}

	title := "fleetsweeper: " + truncate(opts.Finding.Title, 100)
	body := renderPRBody(opts.Finding, opts.Cluster, opts.TargetPath)

	res := Result{
		HeadBranch:  opts.HeadBranch,
		TargetPath:  opts.TargetPath,
		PlannedYAML: opts.Finding.Remediation.YAML,
		PRTitle:     title,
		PRBody:      body,
		DryRun:      !opts.Push,
	}

	if !opts.Push {
		// Caller asked for a plan only. Resolve the base branch best-effort
		// for accuracy if Token is set, otherwise leave it.
		if opts.Token != "" {
			if base, err := defaultBranch(ctx, opts); err == nil {
				res.BaseBranch = base
			}
		}
		if res.BaseBranch == "" {
			res.BaseBranch = opts.BaseBranch
		}
		return res, nil
	}

	if opts.Token == "" {
		return res, errors.New("remediate: --github-token (or $GITHUB_TOKEN) required when pushing")
	}

	baseBranch := opts.BaseBranch
	if baseBranch == "" {
		b, err := defaultBranch(ctx, opts)
		if err != nil {
			return res, fmt.Errorf("detect default branch: %w", err)
		}
		baseBranch = b
	}
	res.BaseBranch = baseBranch

	baseSHA, err := refSHA(ctx, opts, "heads/"+baseBranch)
	if err != nil {
		return res, fmt.Errorf("read base ref: %w", err)
	}
	if err := createRef(ctx, opts, "refs/heads/"+opts.HeadBranch, baseSHA); err != nil {
		return res, fmt.Errorf("create branch: %w", err)
	}
	if err := putFile(ctx, opts, opts.TargetPath, opts.HeadBranch,
		"fleetsweeper: apply "+slug, opts.Finding.Remediation.YAML); err != nil {
		return res, fmt.Errorf("write file: %w", err)
	}
	pr, err := openPR(ctx, opts, title, body, opts.HeadBranch, baseBranch)
	if err != nil {
		return res, fmt.Errorf("create pull request: %w", err)
	}
	res.PRURL = pr.HTMLURL
	res.PRNumber = pr.Number
	return res, nil
}

// renderPRBody composes the pull request description, weaving the finding's
// metadata, kubectl command, and YAML manifest into a coherent narrative a
// reviewer can read in one pass.
func renderPRBody(f report.Finding, cluster, targetPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fleetsweeper detected the following condition and is proposing a remediation.\n\n")
	fmt.Fprintf(&b, "**Cluster:** `%s`\n", cluster)
	fmt.Fprintf(&b, "**Scanner:** `%s`\n", f.Scanner)
	fmt.Fprintf(&b, "**Severity:** `%s`\n\n", f.Severity)
	if f.Description != "" {
		fmt.Fprintf(&b, "**Finding:** %s\n\n", f.Description)
	}
	if f.Remediation != nil && f.Remediation.Command != "" {
		fmt.Fprintf(&b, "**Suggested manual command:**\n\n```shell\n%s\n```\n\n", f.Remediation.Command)
	}
	fmt.Fprintf(&b, "**Manifest written:** `%s`\n\n", targetPath)
	if len(f.Affected) > 0 {
		fmt.Fprintf(&b, "**Affected resources:**\n\n")
		for _, a := range f.Affected {
			fmt.Fprintf(&b, "- `%s`\n", a)
		}
		fmt.Fprintln(&b)
	}
	if f.Remediation != nil && f.Remediation.RunbookURL != "" {
		fmt.Fprintf(&b, "**Runbook:** %s\n\n", f.Remediation.RunbookURL)
	}
	fmt.Fprintf(&b, "\n---\n_Generated by [Fleetsweeper](https://github.com/dcadolph/fleetsweeper). "+
		"Review before merging; this PR will be applied to whatever cluster your GitOps controller targets._\n")
	return b.String()
}

// slugRE replaces runs of non-alphanumeric characters with a dash so the slug
// is safe inside a branch name and a file path.
var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// slugify renders s as a short, branch- and path-safe slug.
func slugify(s string) string {
	lower := strings.ToLower(s)
	cleaned := slugRE.ReplaceAllString(lower, "-")
	cleaned = strings.Trim(cleaned, "-")
	if len(cleaned) > 60 {
		cleaned = cleaned[:60]
		cleaned = strings.TrimRight(cleaned, "-")
	}
	if cleaned == "" {
		return "finding"
	}
	return cleaned
}

// truncate shortens s to n runes, appending an ellipsis when cut.
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

// repoInfo is the JSON shape of GET /repos/{owner}/{repo}.
type repoInfo struct {
	// DefaultBranch is the repo's default base branch.
	DefaultBranch string `json:"default_branch"`
}

// refInfo is the JSON shape of GET /repos/.../git/refs/heads/{branch}.
type refInfo struct {
	// Object holds the SHA being referenced.
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

// createRefPayload is the body for POST /repos/.../git/refs.
type createRefPayload struct {
	// Ref is the new reference, e.g. "refs/heads/feature".
	Ref string `json:"ref"`
	// SHA is the commit SHA the new ref will point at.
	SHA string `json:"sha"`
}

// putFilePayload is the body for PUT /repos/.../contents/{path}.
type putFilePayload struct {
	// Message is the commit message.
	Message string `json:"message"`
	// Content is the base64-encoded file content.
	Content string `json:"content"`
	// Branch is the branch to commit to.
	Branch string `json:"branch"`
	// SHA is the existing file SHA when updating; omit to create.
	SHA string `json:"sha,omitempty"`
}

// prPayload is the body for POST /repos/.../pulls.
type prPayload struct {
	// Title is the pull request title.
	Title string `json:"title"`
	// Head is the source branch.
	Head string `json:"head"`
	// Base is the target branch.
	Base string `json:"base"`
	// Body is the pull request description in Markdown.
	Body string `json:"body"`
}

// prResponse is the relevant JSON subset of POST /repos/.../pulls.
type prResponse struct {
	// HTMLURL is the URL a human visits to view the PR.
	HTMLURL string `json:"html_url"`
	// Number is the PR number within the repo.
	Number int `json:"number"`
}

// defaultBranch returns the default branch of the configured repo.
func defaultBranch(ctx context.Context, o Options) (string, error) {
	var info repoInfo
	if err := apiCall(ctx, o, http.MethodGet,
		"/repos/"+o.Owner+"/"+o.Repo, nil, &info); err != nil {
		return "", err
	}
	if info.DefaultBranch == "" {
		return "", errors.New("repo has no default branch")
	}
	return info.DefaultBranch, nil
}

// refSHA returns the commit SHA of the named ref.
func refSHA(ctx context.Context, o Options, ref string) (string, error) {
	var info refInfo
	if err := apiCall(ctx, o, http.MethodGet,
		"/repos/"+o.Owner+"/"+o.Repo+"/git/refs/"+ref, nil, &info); err != nil {
		return "", err
	}
	return info.Object.SHA, nil
}

// createRef creates a new git ref pointing at sha.
func createRef(ctx context.Context, o Options, ref, sha string) error {
	return apiCall(ctx, o, http.MethodPost,
		"/repos/"+o.Owner+"/"+o.Repo+"/git/refs",
		createRefPayload{Ref: ref, SHA: sha}, nil)
}

// putFile creates or updates a file on the given branch.
func putFile(ctx context.Context, o Options, path, branch, message, body string) error {
	payload := putFilePayload{
		Message: message,
		Branch:  branch,
		Content: base64.StdEncoding.EncodeToString([]byte(body)),
	}
	return apiCall(ctx, o, http.MethodPut,
		"/repos/"+o.Owner+"/"+o.Repo+"/contents/"+path, payload, nil)
}

// openPR opens a pull request.
func openPR(ctx context.Context, o Options, title, body, head, base string) (prResponse, error) {
	var out prResponse
	err := apiCall(ctx, o, http.MethodPost,
		"/repos/"+o.Owner+"/"+o.Repo+"/pulls",
		prPayload{Title: title, Head: head, Base: base, Body: body}, &out)
	return out, err
}

// apiCall is a minimal generic JSON GitHub API client. Encodes body, sends,
// decodes response when out is non-nil, surfaces non-2xx as errors with the
// API's own message included for diagnostics.
func apiCall(ctx context.Context, o Options, method, path string, body any, out any) error {
	url := strings.TrimRight(o.BaseURL, "/") + path
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "fleetsweeper-remediate")
	if o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.Token)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github api %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
