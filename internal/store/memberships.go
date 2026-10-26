package store

import (
	"database/sql"
	"fmt"
)

// scanMemberships reads (group_name, cluster_name) rows ordered by group and cluster into each
// group's clusters and each cluster's groups, both lists sorted by that order.
func scanMemberships(rows *sql.Rows) (byGroup, byCluster map[string][]string, err error) {
	byGroup, byCluster = map[string][]string{}, map[string][]string{}
	for rows.Next() {
		var group, cluster string
		if err := rows.Scan(&group, &cluster); err != nil {
			return nil, nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		byGroup[group] = append(byGroup[group], cluster)
		byCluster[cluster] = append(byCluster[cluster], group)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	return byGroup, byCluster, nil
}
