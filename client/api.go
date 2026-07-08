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
func (c *Client) GetClusterDetail(ctx context.Context, name string) (*ClusterDetail, error) {
	var out ClusterDetail
	if err := c.do(ctx, http.MethodGet, "/api/clusters/"+url.PathEscape(name)+"/detail", nil, nil, &out); err != nil {
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
func (c *Client) Outliers(ctx context.Context, threshold float64) (*OutliersResponse, error) {
	var q url.Values
	if threshold > 0 {
		q = url.Values{"threshold": []string{strconv.FormatFloat(threshold, 'f', -1, 64)}}
	}
	var out OutliersResponse
	if err := c.do(ctx, http.MethodGet, "/api/outliers", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Capacity returns the capacity correlator output for the latest scan.
func (c *Client) Capacity(ctx context.Context) (*CapacityResponse, error) {
	var out CapacityResponse
	if err := c.do(ctx, http.MethodGet, "/api/capacity", nil, nil, &out); err != nil {
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
func (c *Client) Cost(ctx context.Context) (*CostAnalysis, error) {
	var out CostAnalysis
	if err := c.do(ctx, http.MethodGet, "/api/cost", nil, nil, &out); err != nil {
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

// AckFinding records a finding acknowledgement. It requires a bearer token
// unless the server runs with authentication disabled.
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
func (c *Client) Geo(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/geo", nil, nil, &out); err != nil {
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
