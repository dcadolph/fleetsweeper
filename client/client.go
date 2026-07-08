// Package client is a Go SDK for the Fleetsweeper HTTP API. Its types and
// operations mirror internal/server/openapi.yaml, and it depends only on the
// standard library so external programs can vendor it without pulling in the
// server. Construct a Client with New and call one method per API operation.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout bounds a single API call when the caller supplies no custom
// HTTP client.
const DefaultTimeout = 30 * time.Second

// Client calls the Fleetsweeper HTTP API. Construct it with New and share one
// instance across goroutines; the underlying http.Client is safe for
// concurrent use.
type Client struct {
	// baseURL is the API root with any trailing slash trimmed.
	baseURL string
	// token is the bearer token sent on every request. Empty sends no
	// Authorization header, which the server accepts only for read endpoints
	// or when it runs with --insecure.
	token string
	// http is the transport used for every request.
	http *http.Client
	// userAgent is the User-Agent header sent on every request.
	userAgent string
}

// Option configures a Client in New.
type Option func(*Client)

// WithToken sets the bearer token sent on every request. Mutating endpoints
// require it unless the server runs with authentication disabled.
func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

// WithHTTPClient replaces the default HTTP client so callers can control
// timeouts, transports, and proxies.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// WithUserAgent overrides the User-Agent header sent on every request.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// New returns a Client for the API rooted at baseURL. The trailing slash is
// trimmed so path joining is predictable.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		http:      &http.Client{Timeout: DefaultTimeout},
		userAgent: "fleetsweeper-go/1",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// APIError is returned when the server responds with a non-2xx status. It
// carries the decoded error envelope when present so callers can branch on the
// status or application code.
type APIError struct {
	// StatusCode is the HTTP status returned by the server.
	StatusCode int
	// Code is the application error code from the JSON body, zero when absent.
	Code int
	// Message is the server error text, or the raw body when the response was
	// not the standard error envelope.
	Message string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("fleetsweeper: http %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("fleetsweeper: http %d", e.StatusCode)
}

// do executes an API request. It marshals body as JSON when non-nil, applies
// auth and headers, decodes a 2xx JSON body into out when out is non-nil, and
// converts any non-2xx status into an *APIError.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fleetsweeper: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return fmt.Errorf("fleetsweeper: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if out != nil {
		req.Header.Set("Accept", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleetsweeper: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("fleetsweeper: decode response: %w", err)
	}
	return nil
}

// newAPIError reads an error response body and builds an *APIError, preferring
// the standard {error, code} envelope and falling back to the raw body.
func newAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	apiErr := &APIError{StatusCode: resp.StatusCode}
	var env struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != "" {
		apiErr.Message = env.Error
		apiErr.Code = env.Code
	} else {
		apiErr.Message = strings.TrimSpace(string(body))
	}
	return apiErr
}
