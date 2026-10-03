package store

import "context"

// Usage reports per bucket usage for a subject (kind "team" matches buckets of
// that team, every other kind matches buckets owned by the subject) together
// with the subject level quota.
func (s *Store) Usage(ctx context.Context, kind, id string) ([]UsageRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT b.id, b.name, b.owner_id, b.owner_kind, b.team_id,
			b.used_bytes, b.used_objects, b.quota_bytes, b.quota_objects,
			COALESCE(q.max_bytes, 0), COALESCE(q.max_objects, 0)
		FROM buckets b
		LEFT JOIN quotas q ON q.subject_kind = $1::text AND q.subject_id = $2::text
		WHERE ($1::text = 'team' AND b.team_id = $2::text)
		   OR ($1::text <> 'team' AND b.owner_id = $2::text)
		ORDER BY b.name`, kind, id)
	if err != nil {
		return nil, classify(err)
	}
	return scanRows(rows, scanUsageRow)
}

func scanUsageRow(row rowScanner) (UsageRow, error) {
	var u UsageRow
	err := row.Scan(&u.BucketID, &u.BucketName, &u.OwnerID, &u.OwnerKind, &u.TeamID,
		&u.UsedBytes, &u.UsedObjects, &u.QuotaBytes, &u.QuotaObjects,
		&u.SubjectMaxBytes, &u.SubjectMaxObjects)
	return u, err
}

// Stats reports platform wide totals.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM buckets),
		(SELECT count(*) FROM objects),
		(SELECT COALESCE(sum(size), 0) FROM objects),
		(SELECT count(*) FROM blobs),
		(SELECT COALESCE(sum(size), 0) FROM blobs),
		(SELECT count(*) FROM blobs WHERE refcount = 0),
		(SELECT count(*) FROM uploads),
		(SELECT count(*) FROM uploads WHERE expires_at < now()),
		(SELECT count(*) FROM quotas)`).
		Scan(&stats.Buckets, &stats.Objects, &stats.LogicalBytes, &stats.Blobs, &stats.BlobBytes,
			&stats.ZeroRefBlobs, &stats.Uploads, &stats.ExpiredUploads, &stats.Quotas)
	if err != nil {
		return Stats{}, classify(err)
	}
	return stats, nil
}
