package store

import (
	"context"
	"time"
)

// UpsertRef increments the refcount of a blob (and refreshes its size and
// last_seen_at), inserting the row when it does not exist yet.
func (s *Store) UpsertRef(ctx context.Context, hash string, size int64) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO blobs (hash, size, refcount)
		VALUES ($1, $2, 1)
		ON CONFLICT (hash) DO UPDATE SET refcount = blobs.refcount + 1, size = excluded.size, last_seen_at = now()`,
		hash, size)
	return classify(err)
}

// DeleteBlob removes a blob row only when its refcount still matches the
// expected value. It reports whether a row was deleted.
func (s *Store) DeleteBlob(ctx context.Context, hash string, refcount int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM blobs WHERE hash = $1 AND refcount = $2`, hash, refcount)
	if err != nil {
		return false, classify(err)
	}
	return tag.RowsAffected() > 0, nil
}

// BlobHashExists reports whether a blob row exists for hash. It is a single
// primary-key lookup; a missing row is reported as (false, nil), not an error.
func (s *Store) BlobHashExists(ctx context.Context, hash string) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blobs WHERE hash = $1)`, hash).Scan(&exists); err != nil {
		return false, classify(err)
	}
	return exists, nil
}

// ZeroRefBlobs lists unreferenced blobs whose grace period started before
// olderThan.
func (s *Store) ZeroRefBlobs(ctx context.Context, olderThan time.Time, limit int) ([]Blob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT hash, size, refcount, created_at, last_seen_at
		FROM blobs
		WHERE refcount = 0 AND last_seen_at < $1
		ORDER BY last_seen_at
		LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, classify(err)
	}
	return scanRows(rows, scanBlob)
}

func scanBlob(row rowScanner) (Blob, error) {
	var b Blob
	err := row.Scan(&b.Hash, &b.Size, &b.Refcount, &b.CreatedAt, &b.LastSeenAt)
	return b, err
}
