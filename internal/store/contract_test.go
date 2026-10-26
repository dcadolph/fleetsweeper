package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// storeFactory opens an empty Store for one test and arranges its cleanup.
type storeFactory func(t *testing.T) Store

// contractEpoch anchors every timestamp the contract writes. Both backends
// store RFC 3339 seconds, so contract times are whole seconds in UTC.
var contractEpoch = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) //nolint:gochecknoglobals // Not modified, simplifies testing.

// TestSQLiteStoreContract runs the Store contract against SQLite.
func TestSQLiteStoreContract(t *testing.T) {
	t.Parallel()
	runStoreContract(t, func(t *testing.T) Store { return testStore(t) })
}

// TestPostgresStoreContract runs the Store contract against Postgres. It skips
// when FLEETSWEEPER_PG_TEST_DSN is unset.
func TestPostgresStoreContract(t *testing.T) {
	t.Parallel()
	runStoreContract(t, func(t *testing.T) Store { return newTestPostgres(t) })
}

// runStoreContract exercises every Store method with expectations both
// backends must meet. Each case opens its own store so cases run in parallel.
func runStoreContract(t *testing.T, open storeFactory) {
	t.Helper()
	cases := []struct {
		Name string
		Run  func(t *testing.T, st Store)
	}{
		{Name: "scans", Run: contractScans},
		{Name: "save scan record", Run: checkSaveScanRecord},
		{Name: "scan results", Run: contractScanResults},
		{Name: "clusters", Run: contractClusters},
		{Name: "groups", Run: contractGroups},
		{Name: "cluster history", Run: contractClusterHistory},
		{Name: "time range", Run: contractTimeRange},
		{Name: "prune and vacuum", Run: contractPrune},
		{Name: "locations", Run: contractLocations},
		{Name: "acks", Run: contractAcks},
		{Name: "api keys", Run: contractAPIKeys},
		{Name: "audit", Run: contractAudit},
		{Name: "alerts", Run: contractAlerts},
		{Name: "sub-second times", Run: contractSubsecond},
		{Name: "tags", Run: contractTags},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			c.Run(t, open(t))
		})
	}
}

// saveAt saves a one-scanner scan of clusters under id at contractEpoch plus
// offset and fails the test on error.
func saveAt(t *testing.T, st Store, id string, offset time.Duration, clusters ...string) {
	t.Helper()
	results := make(map[string]map[string]scanner.Result, len(clusters))
	for _, c := range clusters {
		results[c] = map[string]scanner.Result{"version": {Scanner: "version", Data: map[string]any{"id": id}}}
	}
	rec := ScanRecord{ID: id, Timestamp: contractEpoch.Add(offset), Clusters: clusters}
	if _, err := st.SaveScanRecord(context.Background(), rec, results); err != nil {
		t.Fatalf("save scan %s: %v", id, err)
	}
}

// scanIDs returns the IDs of recs in order.
func scanIDs(recs []ScanRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

// contractScans checks GetScan and ListScans ordering, tie-break, and limit.
func contractScans(t *testing.T, st Store) {
	ctx := context.Background()
	saveAt(t, st, "0000000000001-a", 0, "east")
	saveAt(t, st, "0000000000003-c", time.Minute, "east")
	saveAt(t, st, "0000000000002-b", time.Minute, "east", "west")

	got, err := st.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	want := []string{"0000000000003-c", "0000000000002-b", "0000000000001-a"}
	if diff := cmp.Diff(want, scanIDs(got)); diff != "" {
		t.Errorf("order mismatch (-want +got):\n%s", diff)
	}
	limited, err := st.ListScans(ctx, 2)
	if err != nil {
		t.Fatalf("list scans limited: %v", err)
	}
	if diff := cmp.Diff(want[:2], scanIDs(limited)); diff != "" {
		t.Errorf("limit mismatch (-want +got):\n%s", diff)
	}

	rec, err := st.GetScan(ctx, "0000000000002-b")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	wantRec := ScanRecord{
		ID: "0000000000002-b", Timestamp: contractEpoch.Add(time.Minute),
		Clusters: []string{"east", "west"}, Scanners: []string{"version"},
	}
	if diff := cmp.Diff(wantRec, *rec); diff != "" {
		t.Errorf("record mismatch (-want +got):\n%s", diff)
	}
	if _, err := st.GetScan(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing scan: want ErrNotFound, got %v", err)
	}
}

// contractScanResults checks results round-trip with State and Reason, and an
// unknown scan yields no results.
func contractScanResults(t *testing.T, st Store) {
	ctx := context.Background()
	want := map[string]map[string]scanner.Result{
		"east": {
			"version": {Scanner: "version", Data: map[string]any{"minor": float64(31)}},
			"certs":   {Scanner: "certs", State: scanner.StateErrored, Reason: "forbidden"},
		},
		"west": {
			"workloads": {
				Scanner: "workloads", State: scanner.StateDegraded, Reason: "1 of 4 reads failed",
				Data: map[string]any{"pods": float64(9), "names": []any{"a", "b"}},
			},
		},
	}
	id, err := st.SaveScan(ctx, []string{"east", "west"}, want)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	got, err := st.GetScanResults(ctx, id)
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("results mismatch (-want +got):\n%s", diff)
	}
	rec, err := st.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if diff := cmp.Diff([]string{"certs", "version", "workloads"}, rec.Scanners); diff != "" {
		t.Errorf("scanners mismatch (-want +got):\n%s", diff)
	}

	none, err := st.GetScanResults(ctx, "missing")
	if err != nil {
		t.Fatalf("get results for missing scan: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("want no results for a missing scan, got %v", none)
	}
}

// contractClusters checks cluster tracking: sorted names, first and last seen
// from the scan timestamps, and group membership.
func contractClusters(t *testing.T, st Store) {
	ctx := context.Background()
	empty, err := st.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("want no clusters, got %v", empty)
	}

	saveAt(t, st, "0000000000001-a", 0, "west", "east")
	saveAt(t, st, "0000000000002-b", time.Hour, "east")
	if err := st.SaveGroup(ctx, "prod", []string{"east"}); err != nil {
		t.Fatalf("save group: %v", err)
	}

	got, err := st.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list clusters: %v", err)
	}
	want := []ClusterRecord{
		{Name: "east", FirstSeen: contractEpoch, LastSeen: contractEpoch.Add(time.Hour), Groups: []string{"prod"}},
		{Name: "west", FirstSeen: contractEpoch, LastSeen: contractEpoch},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("clusters mismatch (-want +got):\n%s", diff)
	}
}

// contractGroups checks group create, replace, list, membership edits,
// delete, and the not-found paths.
func contractGroups(t *testing.T, st Store) {
	ctx := context.Background()
	if _, err := st.GetGroup(ctx, "prod"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing group: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteGroup(ctx, "prod"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing group: want ErrNotFound, got %v", err)
	}

	if err := st.SaveGroup(ctx, "prod", []string{"west", "east"}); err != nil {
		t.Fatalf("save group: %v", err)
	}
	if err := st.SaveGroup(ctx, "prod", []string{"east", "south"}); err != nil {
		t.Fatalf("replace group: %v", err)
	}
	if err := st.SaveGroup(ctx, "edge", nil); err != nil {
		t.Fatalf("save empty group: %v", err)
	}
	g, err := st.GetGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if diff := cmp.Diff(GroupRecord{Name: "prod", Clusters: []string{"east", "south"}}, *g); diff != "" {
		t.Errorf("replaced group mismatch (-want +got):\n%s", diff)
	}

	if err := st.AddClusterToGroup(ctx, "ghost", "asia"); err == nil {
		t.Error("add cluster to a missing group: want an error")
	}
	if err := st.AddClusterToGroup(ctx, "prod", "asia"); err != nil {
		t.Fatalf("add cluster: %v", err)
	}
	if err := st.AddClusterToGroup(ctx, "prod", "asia"); err != nil {
		t.Fatalf("add cluster twice: %v", err)
	}
	if err := st.RemoveClusterFromGroup(ctx, "prod", "south"); err != nil {
		t.Fatalf("remove cluster: %v", err)
	}
	if err := st.RemoveClusterFromGroup(ctx, "prod", "never-there"); err != nil {
		t.Fatalf("remove absent cluster: %v", err)
	}
	groups, err := st.ListGroups(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	want := []GroupRecord{{Name: "edge"}, {Name: "prod", Clusters: []string{"asia", "east"}}}
	if diff := cmp.Diff(want, groups, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("groups mismatch (-want +got):\n%s", diff)
	}

	if err := st.DeleteGroup(ctx, "prod"); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	if _, err := st.GetGroup(ctx, "prod"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get deleted group: want ErrNotFound, got %v", err)
	}
	if err := st.SaveGroup(ctx, "prod", nil); err != nil {
		t.Fatalf("recreate group: %v", err)
	}
	g, err = st.GetGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("get recreated group: %v", err)
	}
	if len(g.Clusters) != 0 {
		t.Errorf("recreated group kept old members: %v", g.Clusters)
	}
}

// contractClusterHistory checks per-cluster history is newest first, breaks
// timestamp ties by scan ID, honors the limit, excludes other clusters, and
// carries each result's State and Reason.
func contractClusterHistory(t *testing.T, st Store) {
	ctx := context.Background()
	degraded := map[string]map[string]scanner.Result{"alpha": {"version": {
		Scanner: "version", Data: map[string]any{"id": "0000000000000-z"},
		State: scanner.StateDegraded, Reason: "nodes: forbidden",
	}}}
	rec := ScanRecord{ID: "0000000000000-z", Timestamp: contractEpoch.Add(-time.Minute), Clusters: []string{"alpha"}}
	if _, err := st.SaveScanRecord(ctx, rec, degraded); err != nil {
		t.Fatalf("save degraded scan: %v", err)
	}
	saveAt(t, st, "0000000000001-a", 0, "alpha", "beta")
	saveAt(t, st, "0000000000002-b", time.Minute, "alpha")
	saveAt(t, st, "0000000000003-c", time.Minute, "alpha")
	saveAt(t, st, "0000000000004-d", 2*time.Minute, "beta")

	got, err := st.GetClusterHistory(ctx, "alpha", 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	want := []ScanResultRecord{
		{ScanID: "0000000000003-c", Cluster: "alpha", Scanner: "version", DataJSON: []byte(`{"id":"0000000000003-c"}`)},
		{ScanID: "0000000000002-b", Cluster: "alpha", Scanner: "version", DataJSON: []byte(`{"id":"0000000000002-b"}`)},
		{ScanID: "0000000000001-a", Cluster: "alpha", Scanner: "version", DataJSON: []byte(`{"id":"0000000000001-a"}`)},
		{
			ScanID: "0000000000000-z", Cluster: "alpha", Scanner: "version", DataJSON: []byte(`{"id":"0000000000000-z"}`),
			State: scanner.StateDegraded, Reason: "nodes: forbidden",
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("history mismatch (-want +got):\n%s", diff)
	}
	limited, err := st.GetClusterHistory(ctx, "alpha", 1)
	if err != nil {
		t.Fatalf("history limited: %v", err)
	}
	if diff := cmp.Diff(want[:1], limited); diff != "" {
		t.Errorf("limited history mismatch (-want +got):\n%s", diff)
	}
}

// contractTimeRange checks GetScansByTimeRange includes both bounds and
// orders newest first.
func contractTimeRange(t *testing.T, st Store) {
	ctx := context.Background()
	saveAt(t, st, "0000000000001-a", 0, "east")
	saveAt(t, st, "0000000000002-b", time.Hour, "east")
	saveAt(t, st, "0000000000003-c", 2*time.Hour, "east")
	saveAt(t, st, "0000000000004-d", 3*time.Hour, "east")

	got, err := st.GetScansByTimeRange(ctx, contractEpoch.Add(time.Hour), contractEpoch.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("time range: %v", err)
	}
	if diff := cmp.Diff([]string{"0000000000003-c", "0000000000002-b"}, scanIDs(got)); diff != "" {
		t.Errorf("range mismatch (-want +got):\n%s", diff)
	}
}

// contractPrune checks Prune deletes only older scans, removes their results,
// and reports the count, and that Vacuum succeeds.
func contractPrune(t *testing.T, st Store) {
	ctx := context.Background()
	saveAt(t, st, "0000000000001-a", 0, "east")
	saveAt(t, st, "0000000000002-b", time.Hour, "east")
	saveAt(t, st, "0000000000003-c", 2*time.Hour, "east")

	n, err := st.Prune(ctx, contractEpoch.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if diff := cmp.Diff(2, n); diff != "" {
		t.Errorf("pruned count mismatch (-want +got):\n%s", diff)
	}
	left, err := st.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list after prune: %v", err)
	}
	if diff := cmp.Diff([]string{"0000000000003-c"}, scanIDs(left)); diff != "" {
		t.Errorf("survivors mismatch (-want +got):\n%s", diff)
	}
	results, err := st.GetScanResults(ctx, "0000000000001-a")
	if err != nil {
		t.Fatalf("results of pruned scan: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("pruned scan kept results: %v", results)
	}
	if err := st.Vacuum(ctx); err != nil {
		t.Errorf("vacuum: %v", err)
	}
}

// contractLocations checks location upsert, get, sorted list, and delete.
func contractLocations(t *testing.T, st Store) {
	ctx := context.Background()
	missing, err := st.GetLocation(ctx, "east")
	if err != nil || missing != nil {
		t.Errorf("get unset location: want nil, nil, got %v, %v", missing, err)
	}

	before := time.Now().UTC().Truncate(time.Second)
	for _, loc := range []LocationRecord{
		{Cluster: "west", Lat: 37.77, Lng: -122.42},
		{Cluster: "east", Lat: 40.71, Lng: -74.01, Site: "edge-nyc-42", Notes: "rack 3"},
		{Cluster: "west", Lat: 47.61, Lng: -122.33, Site: "site-sea-1"},
	} {
		if err := st.SetLocation(ctx, loc); err != nil {
			t.Fatalf("set location %s: %v", loc.Cluster, err)
		}
	}
	got, err := st.ListLocations(ctx)
	if err != nil {
		t.Fatalf("list locations: %v", err)
	}
	want := []LocationRecord{
		{Cluster: "east", Lat: 40.71, Lng: -74.01, Site: "edge-nyc-42", Notes: "rack 3"},
		{Cluster: "west", Lat: 47.61, Lng: -122.33, Site: "site-sea-1"},
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(LocationRecord{}, "UpdatedAt")); diff != "" {
		t.Errorf("locations mismatch (-want +got):\n%s", diff)
	}
	for _, l := range got {
		if l.UpdatedAt.Before(before) {
			t.Errorf("location %s UpdatedAt %v is before the write at %v", l.Cluster, l.UpdatedAt, before)
		}
	}
	one, err := st.GetLocation(ctx, "east")
	if err != nil {
		t.Fatalf("get location: %v", err)
	}
	if diff := cmp.Diff(want[0], *one, cmpopts.IgnoreFields(LocationRecord{}, "UpdatedAt")); diff != "" {
		t.Errorf("location mismatch (-want +got):\n%s", diff)
	}

	if err := st.DeleteLocation(ctx, "east"); err != nil {
		t.Fatalf("delete location: %v", err)
	}
	if err := st.DeleteLocation(ctx, "east"); err != nil {
		t.Fatalf("delete location twice: %v", err)
	}
	gone, err := st.GetLocation(ctx, "east")
	if err != nil || gone != nil {
		t.Errorf("get deleted location: want nil, nil, got %v, %v", gone, err)
	}
}

// contractAcks checks ack upsert, list, IsAcked, snooze expiry, delete, and
// the empty-fingerprint refusal.
func contractAcks(t *testing.T, st Store) {
	ctx := context.Background()
	if err := st.SaveAck(ctx, AckRecord{Cluster: "east"}); err == nil {
		t.Error("save ack without fingerprint: want an error")
	}

	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	acks := []AckRecord{
		{Fingerprint: "fp-1", Cluster: "east", Scanner: "rbac", Title: "old title", AckBy: "ops", CreatedAt: contractEpoch},
		{Fingerprint: "fp-1", Cluster: "east", Scanner: "rbac", Title: "new title", AckBy: "ops", Reason: "known",
			CreatedAt: contractEpoch.Add(time.Minute)},
		{Fingerprint: "fp-2", Cluster: "west", Scanner: "certs", Title: "snoozed", SnoozeUntil: future,
			CreatedAt: contractEpoch},
		{Fingerprint: "fp-3", Cluster: "west", Scanner: "certs", Title: "expired",
			SnoozeUntil: time.Now().UTC().Add(-time.Hour).Truncate(time.Second), CreatedAt: contractEpoch},
	}
	for _, a := range acks {
		if err := st.SaveAck(ctx, a); err != nil {
			t.Fatalf("save ack %s: %v", a.Fingerprint, err)
		}
	}

	got, err := st.ListAcks(ctx)
	if err != nil {
		t.Fatalf("list acks: %v", err)
	}
	want := []AckRecord{acks[1], acks[2]}
	sortAcks := cmpopts.SortSlices(func(a, b AckRecord) bool { return a.Fingerprint < b.Fingerprint })
	if diff := cmp.Diff(want, got, sortAcks); diff != "" {
		t.Errorf("acks mismatch (-want +got):\n%s", diff)
	}
	for fp, wantAcked := range map[string]bool{"fp-1": true, "fp-2": true, "fp-3": false, "fp-none": false} {
		acked, err := st.IsAcked(ctx, fp)
		if err != nil {
			t.Fatalf("is acked %s: %v", fp, err)
		}
		if acked != wantAcked {
			t.Errorf("IsAcked(%s) = %v, want %v", fp, acked, wantAcked)
		}
	}

	if err := st.DeleteAck(ctx, "fp-1"); err != nil {
		t.Fatalf("delete ack: %v", err)
	}
	if err := st.DeleteAck(ctx, "fp-1"); err != nil {
		t.Fatalf("delete ack twice: %v", err)
	}
	if acked, _ := st.IsAcked(ctx, "fp-1"); acked {
		t.Error("deleted ack still reports acked")
	}
}

// contractAPIKeys checks the API key lifecycle: save, lookups, newest-first
// list including revoked keys, revoke, touch, and the error paths.
func contractAPIKeys(t *testing.T, st Store) {
	ctx := context.Background()
	if _, err := st.GetAPIKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing key: want ErrNotFound, got %v", err)
	}
	if _, err := st.GetAPIKeyByHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing hash: want ErrNotFound, got %v", err)
	}
	if err := st.RevokeAPIKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke missing key: want ErrNotFound, got %v", err)
	}

	older := APIKeyRecord{
		ID: "key-old", TokenHash: "hash-old", Name: "ci", Role: RoleOperator,
		ClusterScope: []string{"group:prod", "edge-1"}, CreatedAt: contractEpoch,
		ExpiresAt: contractEpoch.Add(48 * time.Hour), CreatedBy: "admin",
	}
	newer := APIKeyRecord{
		ID: "key-new", TokenHash: "hash-new", Name: "dash", Role: RoleAdmin,
		CreatedAt: contractEpoch.Add(time.Hour),
	}
	for _, k := range []APIKeyRecord{older, newer} {
		if err := st.SaveAPIKey(ctx, k); err != nil {
			t.Fatalf("save key %s: %v", k.ID, err)
		}
	}
	dup := older
	dup.ID = "key-dup"
	if err := st.SaveAPIKey(ctx, dup); err == nil {
		t.Error("save duplicate token hash: want an error")
	}
	bad := newer
	bad.ID, bad.TokenHash, bad.Role = "key-bad", "hash-bad", "superuser"
	if err := st.SaveAPIKey(ctx, bad); err == nil {
		t.Error("save unknown role: want an error")
	}

	byHash, err := st.GetAPIKeyByHash(ctx, "hash-old")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if diff := cmp.Diff(older, *byHash); diff != "" {
		t.Errorf("key by hash mismatch (-want +got):\n%s", diff)
	}
	byID, err := st.GetAPIKey(ctx, "key-new")
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	wantNew := newer
	wantNew.ClusterScope = []string{"*"}
	if diff := cmp.Diff(wantNew, *byID); diff != "" {
		t.Errorf("key by id mismatch (-want +got):\n%s", diff)
	}

	touched := contractEpoch.Add(3 * time.Hour)
	if err := st.TouchAPIKey(ctx, "key-old", touched); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err := st.RevokeAPIKey(ctx, "key-old"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := st.RevokeAPIKey(ctx, "key-old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke twice: want ErrNotFound, got %v", err)
	}

	list, err := st.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	ids := make([]string, 0, len(list))
	for _, k := range list {
		ids = append(ids, k.ID)
	}
	if diff := cmp.Diff([]string{"key-new", "key-old"}, ids); diff != "" {
		t.Errorf("list order mismatch (-want +got):\n%s", diff)
	}
	revoked := list[1]
	if !revoked.LastUsedAt.Equal(touched) {
		t.Errorf("LastUsedAt = %v, want %v", revoked.LastUsedAt, touched)
	}
	if revoked.RevokedAt.IsZero() {
		t.Error("RevokedAt not set after revoke")
	}
}

// contractAudit checks audit entries list newest first, compose every filter,
// honor the limit, and prune by age.
func contractAudit(t *testing.T, st Store) {
	ctx := context.Background()
	entries := []AuditEntry{
		{ID: "a1", ActorID: "alpha", ActorName: "Alpha", ActorRole: RoleAdmin, Method: "POST", Path: "/api/scan",
			Status: 202, RemoteAddr: "10.0.0.1", UserAgent: "curl", DurationMS: 12, Timestamp: contractEpoch},
		{ID: "a2", ActorID: "beta", Method: "POST", Path: "/api/scan", Status: 500, Error: "boom",
			Timestamp: contractEpoch.Add(time.Hour)},
		{ID: "a3", ActorID: "alpha", Method: "DELETE", Path: "/api/groups/x", Status: 403,
			Timestamp: contractEpoch.Add(2 * time.Hour)},
	}
	for _, e := range entries {
		if err := st.SaveAuditEntry(ctx, e); err != nil {
			t.Fatalf("save audit %s: %v", e.ID, err)
		}
	}
	if err := st.SaveAuditEntry(ctx, AuditEntry{Method: "GET", Path: "/x", Status: 200}); err != nil {
		t.Fatalf("save audit with generated id and time: %v", err)
	}

	tests := []struct {
		Name    string
		Opts    AuditListOptions
		WantIDs []string
	}{
		{Name: "Test 0: Actor filter, newest first.", Opts: AuditListOptions{ActorID: "alpha"},
			WantIDs: []string{"a3", "a1"}},
		{Name: "Test 1: Status floor.", Opts: AuditListOptions{MinStatus: 400, Since: contractEpoch},
			WantIDs: []string{"a3", "a2"}},
		{Name: "Test 2: Since is exclusive.", Opts: AuditListOptions{Since: contractEpoch.Add(time.Hour), ActorID: "alpha"},
			WantIDs: []string{"a3"}},
		{Name: "Test 3: Limit.", Opts: AuditListOptions{ActorID: "alpha", Limit: 1}, WantIDs: []string{"a3"}},
	}
	for _, test := range tests {
		got, err := st.ListAuditEntries(ctx, test.Opts)
		if err != nil {
			t.Fatalf("%s list: %v", test.Name, err)
		}
		ids := make([]string, 0, len(got))
		for _, e := range got {
			ids = append(ids, e.ID)
		}
		if diff := cmp.Diff(test.WantIDs, ids); diff != "" {
			t.Errorf("%s mismatch (-want +got):\n%s", test.Name, diff)
		}
	}
	full, err := st.ListAuditEntries(ctx, AuditListOptions{ActorID: "alpha", MinStatus: 200, Limit: 10})
	if err != nil {
		t.Fatalf("list full: %v", err)
	}
	if diff := cmp.Diff(entries[0], full[len(full)-1]); diff != "" {
		t.Errorf("entry round trip mismatch (-want +got):\n%s", diff)
	}
	generated, err := st.ListAuditEntries(ctx, AuditListOptions{Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("list generated: %v", err)
	}
	if len(generated) != 1 || generated[0].ID == "" || generated[0].Timestamp.IsZero() {
		t.Errorf("want one entry with a generated id and time, got %+v", generated)
	}

	n, err := st.PruneAuditEntries(ctx, contractEpoch.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("prune audit: %v", err)
	}
	if diff := cmp.Diff(2, n); diff != "" {
		t.Errorf("pruned audit count mismatch (-want +got):\n%s", diff)
	}
}

// contractSubsecond checks audit and alert ordering, Since, and prune hold at
// sub-second precision, where trimmed RFC 3339 text does not sort.
func contractSubsecond(t *testing.T, st Store) {
	ctx := context.Background()
	offsets := map[string]time.Duration{"s0": 0, "s100": 100 * time.Millisecond, "s150": 150 * time.Millisecond}
	for id, off := range offsets {
		at := contractEpoch.Add(off)
		if err := st.SaveAuditEntry(ctx, AuditEntry{ID: id, Method: "GET", Path: "/", Status: 200, Timestamp: at}); err != nil {
			t.Fatalf("save audit %s: %v", id, err)
		}
		alert := AlertRecord{Fingerprint: id, Cluster: "east", Status: "firing", AlertName: "A", ReceivedAt: at}
		if err := st.UpsertAlert(ctx, alert); err != nil {
			t.Fatalf("upsert alert %s: %v", id, err)
		}
	}

	audit, err := st.ListAuditEntries(ctx, AuditListOptions{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	alerts, err := st.ListAlerts(ctx, AlertListOptions{})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	gotAudit, gotAlerts := []string{}, []string{}
	for _, e := range audit {
		gotAudit = append(gotAudit, e.ID)
	}
	for _, a := range alerts {
		gotAlerts = append(gotAlerts, a.Fingerprint)
	}
	want := []string{"s150", "s100", "s0"}
	if diff := cmp.Diff(want, gotAudit); diff != "" {
		t.Errorf("audit order mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want, gotAlerts); diff != "" {
		t.Errorf("alert order mismatch (-want +got):\n%s", diff)
	}

	since := contractEpoch.Add(100 * time.Millisecond)
	recent, err := st.ListAuditEntries(ctx, AuditListOptions{Since: since})
	if err != nil {
		t.Fatalf("list audit since: %v", err)
	}
	if len(recent) != 1 || recent[0].ID != "s150" {
		t.Errorf("audit since %v: want [s150], got %+v", since, recent)
	}
	recentAlerts, err := st.ListAlerts(ctx, AlertListOptions{Since: since})
	if err != nil {
		t.Fatalf("list alerts since: %v", err)
	}
	if len(recentAlerts) != 1 || recentAlerts[0].Fingerprint != "s150" {
		t.Errorf("alerts since %v: want [s150], got %+v", since, recentAlerts)
	}

	cutoff := contractEpoch.Add(120 * time.Millisecond)
	if n, err := st.PruneAuditEntries(ctx, cutoff); err != nil || n != 2 {
		t.Errorf("prune audit before %v: want 2, nil, got %d, %v", cutoff, n, err)
	}
	if n, err := st.PruneAlerts(ctx, cutoff); err != nil || n != 2 {
		t.Errorf("prune alerts before %v: want 2, nil, got %d, %v", cutoff, n, err)
	}
}

// contractAlerts checks alert upsert by fingerprint, get, filtered and
// ordered list, and prune.
func contractAlerts(t *testing.T, st Store) {
	ctx := context.Background()
	if _, err := st.GetAlert(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing alert: want ErrNotFound, got %v", err)
	}

	firing := AlertRecord{
		Fingerprint: "al-1", Cluster: "east", Status: "firing", AlertName: "NodeDown", Severity: "critical",
		Summary: "node gone", StartsAt: contractEpoch, ReceivedAt: contractEpoch,
		Labels: map[string]string{"node": "n1"}, Annotations: map[string]string{"runbook": "r"},
		GeneratorURL: "http://prom/graph",
	}
	resolved := firing
	resolved.Status, resolved.EndsAt, resolved.ReceivedAt = "resolved", contractEpoch.Add(time.Hour), contractEpoch.Add(time.Hour)
	other := AlertRecord{
		Fingerprint: "al-2", Cluster: "west", Status: "firing", AlertName: "DiskFull", Severity: "warning",
		ReceivedAt: contractEpoch.Add(30 * time.Minute), Labels: map[string]string{}, Annotations: map[string]string{},
	}
	for _, a := range []AlertRecord{firing, other, resolved} {
		if err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatalf("upsert alert %s: %v", a.Fingerprint, err)
		}
	}
	got, err := st.GetAlert(ctx, "al-1")
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if diff := cmp.Diff(resolved, *got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("alert mismatch (-want +got):\n%s", diff)
	}

	tests := []struct {
		Name    string
		Opts    AlertListOptions
		WantFPs []string
	}{
		{Name: "Test 0: All, newest received first.", Opts: AlertListOptions{}, WantFPs: []string{"al-1", "al-2"}},
		{Name: "Test 1: Cluster.", Opts: AlertListOptions{Cluster: "west"}, WantFPs: []string{"al-2"}},
		{Name: "Test 2: Status.", Opts: AlertListOptions{Status: "resolved"}, WantFPs: []string{"al-1"}},
		{Name: "Test 3: Severity.", Opts: AlertListOptions{Severity: "warning"}, WantFPs: []string{"al-2"}},
		{Name: "Test 4: Since is exclusive.", Opts: AlertListOptions{Since: contractEpoch.Add(30 * time.Minute)},
			WantFPs: []string{"al-1"}},
		{Name: "Test 5: Limit.", Opts: AlertListOptions{Limit: 1}, WantFPs: []string{"al-1"}},
	}
	for _, test := range tests {
		list, err := st.ListAlerts(ctx, test.Opts)
		if err != nil {
			t.Fatalf("%s list: %v", test.Name, err)
		}
		fps := make([]string, 0, len(list))
		for _, a := range list {
			fps = append(fps, a.Fingerprint)
		}
		if diff := cmp.Diff(test.WantFPs, fps); diff != "" {
			t.Errorf("%s mismatch (-want +got):\n%s", test.Name, diff)
		}
	}

	n, err := st.PruneAlerts(ctx, contractEpoch.Add(45*time.Minute))
	if err != nil {
		t.Fatalf("prune alerts: %v", err)
	}
	if diff := cmp.Diff(1, n); diff != "" {
		t.Errorf("pruned alert count mismatch (-want +got):\n%s", diff)
	}
	if _, err := st.GetAlert(ctx, "al-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get pruned alert: want ErrNotFound, got %v", err)
	}
}

// contractTags checks tag upsert, per-cluster and fleet-wide reads, and
// idempotent delete.
func contractTags(t *testing.T, st Store) {
	ctx := context.Background()
	empty, err := st.GetClusterTags(ctx, "east")
	if err != nil {
		t.Fatalf("get empty tags: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Errorf("want an empty non-nil map, got %#v", empty)
	}
	if err := st.SetClusterTag(ctx, "east", "", "x"); err == nil {
		t.Error("set tag with empty key: want an error")
	}

	for _, kv := range [][3]string{
		{"east", "env", "dev"}, {"east", "env", "prod"}, {"east", "region", "us"}, {"west", "env", "prod"},
	} {
		if err := st.SetClusterTag(ctx, kv[0], kv[1], kv[2]); err != nil {
			t.Fatalf("set tag %v: %v", kv, err)
		}
	}
	got, err := st.GetClusterTags(ctx, "east")
	if err != nil {
		t.Fatalf("get tags: %v", err)
	}
	if diff := cmp.Diff(map[string]string{"env": "prod", "region": "us"}, got); diff != "" {
		t.Errorf("tags mismatch (-want +got):\n%s", diff)
	}

	if err := st.DeleteClusterTag(ctx, "east", "region"); err != nil {
		t.Fatalf("delete tag: %v", err)
	}
	if err := st.DeleteClusterTag(ctx, "east", "region"); err != nil {
		t.Fatalf("delete tag twice: %v", err)
	}
	all, err := st.ListClusterTags(ctx)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	want := map[string]map[string]string{"east": {"env": "prod"}, "west": {"env": "prod"}}
	if diff := cmp.Diff(want, all); diff != "" {
		t.Errorf("fleet tags mismatch (-want +got):\n%s", diff)
	}
}
