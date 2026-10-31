package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Healthz reports process liveness. It returns nil when the server is alive.
func (c *Client) Healthz(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil, nil)
}

// Readyz reports readiness by pinging the store. It returns an *APIError with
// status 503 when the store is unreachable.
func (c *Client) Readyz(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/readyz", nil, nil, nil)
}

// ListScans returns recent scans, newest first. A non-positive limit uses the
// server default.
func (c *Client) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	var q url.Values
	if limit > 0 {
		q = url.Values{"limit": []string{strconv.Itoa(limit)}}
	}
	var out []ScanRecord
	if err := c.do(ctx, http.MethodGet, "/api/scans", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// TriggerScan requests a new scan. It returns the accepted scan identifier, or
// an *APIError with status 429 when a scan is already in progress.
func (c *Client) TriggerScan(ctx context.Context, req TriggerScanRequest) (*TriggerScanResponse, error) {
	var out TriggerScanResponse
	if err := c.do(ctx, http.MethodPost, "/api/scans", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetScan returns a scan record by identifier.
func (c *Client) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	var out ScanRecord
	if err := c.do(ctx, http.MethodGet, "/api/scans/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetScanReport returns the full computed report for a scan.
func (c *Client) GetScanReport(ctx context.Context, id string) (*Report, error) {
	var out Report
	if err := c.do(ctx, http.MethodGet, "/api/scans/"+url.PathEscape(id)+"/report", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListClusters returns all known clusters with their first and last seen times.
func (c *Client) ListClusters(ctx context.Context) ([]ClusterRecord, error) {
	var out []ClusterRecord
	if err := c.do(ctx, http.MethodGet, "/api/clusters", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetClusterDetail returns full scanner data, health, and findings for a
// cluster.
func (c *Client) GetClusterDetail(ctx context.Context, name string, opts ...ReadOption) (*ClusterDetail, error) {
	var out ClusterDetail
	q := readQuery(nil, opts)
	if err := c.do(ctx, http.MethodGet, "/api/clusters/"+url.PathEscape(name)+"/detail", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListGroups returns all cluster groups with their members.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	if err := c.do(ctx, http.MethodGet, "/api/groups", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateGroup creates a cluster group. It requires a bearer token unless the
// server runs with authentication disabled.
func (c *Client) CreateGroup(ctx context.Context, req CreateGroupRequest) error {
	return c.do(ctx, http.MethodPost, "/api/groups", nil, req, nil)
}

// DeleteGroup removes a cluster group by name.
func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/api/groups/"+url.PathEscape(name), nil, nil, nil)
}

// Trends returns fleet-wide trend analysis. The response shape is not yet fixed
// in the OpenAPI document, so it is returned as raw JSON. A non-positive scans
// count uses the server default.
func (c *Client) Trends(ctx context.Context, scans int) (json.RawMessage, error) {
	var q url.Values
	if scans > 0 {
		q = url.Values{"scans": []string{strconv.Itoa(scans)}}
	}
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/trends", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ClusterTrends returns per-cluster trend analysis. The response shape is not
// yet fixed in the OpenAPI document, so it is returned as raw JSON.
func (c *Client) ClusterTrends(ctx context.Context, cluster string) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/trends/"+url.PathEscape(cluster), nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Outliers returns outlier detection for the latest scan. A non-positive
// threshold uses the server default.
func (c *Client) Outliers(ctx context.Context, threshold float64, opts ...ReadOption) (*OutliersResponse, error) {
	var q url.Values
	if threshold > 0 {
		q = url.Values{"threshold": []string{strconv.FormatFloat(threshold, 'f', -1, 64)}}
	}
	q = readQuery(q, opts)
	var out OutliersResponse
	if err := c.do(ctx, http.MethodGet, "/api/outliers", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Capacity returns the capacity correlator output for the latest scan.
func (c *Client) Capacity(ctx context.Context, opts ...ReadOption) (*CapacityResponse, error) {
	var out CapacityResponse
	if err := c.do(ctx, http.MethodGet, "/api/capacity", readQuery(nil, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FleetForecast forecasts the next fleet score from history. A non-positive
// scans count uses the server default.
func (c *Client) FleetForecast(ctx context.Context, scans int) (*FleetForecastResponse, error) {
	var q url.Values
	if scans > 0 {
		q = url.Values{"scans": []string{strconv.Itoa(scans)}}
	}
	var out FleetForecastResponse
	if err := c.do(ctx, http.MethodGet, "/api/forecast/fleet-score", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClustersForecast returns per-cluster fleet-score forecasts ranked by
// projected delta.
func (c *Client) ClustersForecast(ctx context.Context) (*ClustersForecastResponse, error) {
	var out ClustersForecastResponse
	if err := c.do(ctx, http.MethodGet, "/api/forecast/clusters", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Cost returns cost correlation for the latest scan. With no cost CSV loaded
// the server returns an empty USD analysis rather than an error.
func (c *Client) Cost(ctx context.Context, opts ...ReadOption) (*CostAnalysis, error) {
	var out CostAnalysis
	if err := c.do(ctx, http.MethodGet, "/api/cost", readQuery(nil, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Integrations reports which integrations are configured.
func (c *Client) Integrations(ctx context.Context) ([]IntegrationStatus, error) {
	var out struct {
		Items []IntegrationStatus `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/integrations", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// ListAcks returns active finding acknowledgements.
func (c *Client) ListAcks(ctx context.Context) ([]AckRecord, error) {
	var out []AckRecord
	if err := c.do(ctx, http.MethodGet, "/api/acks", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AckFinding records a finding acknowledgement. The fingerprint must belong to
// a finding in the latest report, or the server answers 404, and the caller's
// key must reach that finding's cluster. It requires a bearer token unless the
// server runs with authentication disabled.
func (c *Client) AckFinding(ctx context.Context, fingerprint string, req AckRequest) (*AckRecord, error) {
	var out AckRecord
	path := "/api/findings/" + url.PathEscape(fingerprint) + "/ack"
	if err := c.do(ctx, http.MethodPost, path, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteFindingAck removes a finding acknowledgement by fingerprint.
func (c *Client) DeleteFindingAck(ctx context.Context, fingerprint string) error {
	path := "/api/findings/" + url.PathEscape(fingerprint) + "/ack"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// AlertQuery filters ListAlerts. Zero-valued fields are omitted.
type AlertQuery struct {
	// Cluster restricts results to one cluster.
	Cluster string
	// Status restricts results to firing or resolved alerts.
	Status string
	// Severity restricts results to one severity label value.
	Severity string
	// Since restricts results to alerts received after this time.
	Since time.Time
	// Limit caps the number of alerts returned.
	Limit int
}

// values renders the query as URL parameters, omitting zero-valued fields.
func (q AlertQuery) values() url.Values {
	v := url.Values{}
	if q.Cluster != "" {
		v.Set("cluster", q.Cluster)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Severity != "" {
		v.Set("severity", q.Severity)
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}

// ListAlerts returns inbound alerts from AlertManager and Falco, filtered by
// query.
func (c *Client) ListAlerts(ctx context.Context, query AlertQuery) (*AlertsResponse, error) {
	var out AlertsResponse
	if err := c.do(ctx, http.MethodGet, "/api/alerts", query.values(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AckAlert acknowledges an inbound alert. It returns an *APIError with status
// 404 when the fingerprint is unknown.
func (c *Client) AckAlert(ctx context.Context, fingerprint string, req AckAlertRequest) (*AckRecord, error) {
	var out AckRecord
	path := "/api/alerts/" + url.PathEscape(fingerprint) + "/ack"
	if err := c.do(ctx, http.MethodPost, path, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClusterTimeline returns an interleaved chronological view of one cluster. A
// non-positive limit uses the server default.
func (c *Client) ClusterTimeline(ctx context.Context, name string, limit int) (*TimelineResponse, error) {
	var q url.Values
	if limit > 0 {
		q = url.Values{"limit": []string{strconv.Itoa(limit)}}
	}
	var out TimelineResponse
	if err := c.do(ctx, http.MethodGet, "/api/clusters/"+url.PathEscape(name)+"/timeline", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Geo returns cluster placements and health for the latest scan. The response
// shape is not yet fixed in the OpenAPI document, so it is returned as raw
// JSON.
func (c *Client) Geo(ctx context.Context, opts ...ReadOption) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/geo", readQuery(nil, opts), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListLocations returns manual location overrides. The response shape is not
// yet fixed in the OpenAPI document, so it is returned as raw JSON.
func (c *Client) ListLocations(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/locations", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetLocation upserts a manual location override for a cluster. It requires a
// bearer token unless the server runs with authentication disabled.
func (c *Client) SetLocation(ctx context.Context, cluster string, req LocationRequest) error {
	return c.do(ctx, http.MethodPut, "/api/locations/"+url.PathEscape(cluster), nil, req, nil)
}

// DeleteLocation removes a manual location override for a cluster.
func (c *Client) DeleteLocation(ctx context.Context, cluster string) error {
	return c.do(ctx, http.MethodDelete, "/api/locations/"+url.PathEscape(cluster), nil, nil, nil)
}

// Contexts returns the kubeconfig contexts available to the server.
func (c *Client) Contexts(ctx context.Context) ([]Context, error) {
	var out []Context
	if err := c.do(ctx, http.MethodGet, "/api/contexts", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReadOption adjusts the query of a read that reports on one scan.
type ReadOption func(url.Values)

// WithScan makes a read report on the scan with the given ID instead of the
// latest one.
func WithScan(id string) ReadOption {
	return func(q url.Values) { q.Set("scan", id) }
}

// readQuery applies opts to q, allocating it when needed, and returns nil
// when the result is empty.
func readQuery(q url.Values, opts []ReadOption) url.Values {
	if len(opts) == 0 {
		return q
	}
	if q == nil {
		q = url.Values{}
	}
	for _, o := range opts {
		o(q)
	}
	return q
}

// Scanners returns every scanner with its label, description, and category.
func (c *Client) Scanners(ctx context.Context) ([]ScannerInfo, error) {
	var out []ScannerInfo
	if err := c.do(ctx, http.MethodGet, "/api/scanners", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Cohorts returns the cohort partition of the latest scan with the outliers
// each cohort finds against its own baseline. A non-positive threshold uses
// the server default.
func (c *Client) Cohorts(ctx context.Context, threshold float64, opts ...ReadOption) (*CohortsResponse, error) {
	var q url.Values
	if threshold > 0 {
		q = url.Values{"threshold": []string{strconv.FormatFloat(threshold, 'f', -1, 64)}}
	}
	var out CohortsResponse
	if err := c.do(ctx, http.MethodGet, "/api/cohorts", readQuery(q, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Distributions returns the distributions behind the fleet norm for one scan.
func (c *Client) Distributions(ctx context.Context, query DistributionQuery, opts ...ReadOption) (*DistributionsResponse, error) {
	q := url.Values{}
	for k, v := range map[string]string{"scope": query.Scope, "scanner": query.Scanner, "field": query.Field} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var out DistributionsResponse
	if err := c.do(ctx, http.MethodGet, "/api/distributions", readQuery(q, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DistributionHistory returns one field's distribution across the most
// recent scans, oldest first. An empty scope means fleet and a non-positive
// scans count uses the server default.
func (c *Client) DistributionHistory(ctx context.Context, scanner, field, scope string, scans int) (*HistoryResponse, error) {
	q := url.Values{"scanner": []string{scanner}, "field": []string{field}}
	if scope != "" {
		q.Set("scope", scope)
	}
	if scans > 0 {
		q.Set("scans", strconv.Itoa(scans))
	}
	var out HistoryResponse
	if err := c.do(ctx, http.MethodGet, "/api/distributions/history", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScoreAttribution returns the fleet score of one scan and the ledger behind
// it.
func (c *Client) ScoreAttribution(ctx context.Context, opts ...ReadOption) (*AttributionResponse, error) {
	var out AttributionResponse
	if err := c.do(ctx, http.MethodGet, "/api/score/attribution", readQuery(nil, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Drift returns the drift ledger over the window query selects.
func (c *Client) Drift(ctx context.Context, query DriftQuery) (*DriftLedger, error) {
	q := url.Values{}
	if query.Scans > 0 {
		q.Set("scans", strconv.Itoa(query.Scans))
	}
	if !query.Since.IsZero() {
		q.Set("since", query.Since.UTC().Format(time.RFC3339))
	}
	if !query.Until.IsZero() {
		q.Set("until", query.Until.UTC().Format(time.RFC3339))
	}
	var out DriftLedger
	if err := c.do(ctx, http.MethodGet, "/api/drift", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CohortMap returns the two-dimensional cohort map of one scan.
func (c *Client) CohortMap(ctx context.Context, opts ...ReadOption) (*CohortMapResponse, error) {
	var out CohortMapResponse
	if err := c.do(ctx, http.MethodGet, "/api/cohorts/map", readQuery(nil, opts), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WhatIf projects the score and norm if one cluster's field were fixed. The
// server writes nothing.
func (c *Client) WhatIf(ctx context.Context, req WhatIfRequest) (*WhatIfResponse, error) {
	var out WhatIfResponse
	if err := c.do(ctx, http.MethodPost, "/api/whatif", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
