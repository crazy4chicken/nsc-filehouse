package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/crazy4chicken/nsc-filehouse/internal/id"
)

// BucketFilter selects and paginates ListBuckets. Empty fields match everything.
type BucketFilter struct {
	OwnerID    string
	OwnerKind  string
	TeamID     string
	NamePrefix string
	Cursor     string
	Limit      int
}

// CreateBucket inserts a bucket. The caller supplies ids and applies default
// quotas; store only generates a missing id.
func (s *Store) CreateBucket(ctx context.Context, b Bucket) (Bucket, error) {
	if b.ID == "" {
		b.ID = id.New()
	}
	if b.OwnerKind == "" {
		return Bucket{}, errors.New("bucket owner kind is required")
	}
	row := s.pool.QueryRow(ctx, `INSERT INTO buckets (id, name, owner_id, owner_kind, team_id, description, quota_bytes, quota_objects)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+bucketColumns,
		b.ID, b.Name, b.OwnerID, b.OwnerKind, b.TeamID, b.Description, b.QuotaBytes, b.QuotaObjects)
	out, err := scanBucket(row)
	if err != nil {
		return Bucket{}, classify(err)
	}
	return out, nil
}

// GetBucketByName returns the bucket with the given unique name.
func (s *Store) GetBucketByName(ctx context.Context, name string) (Bucket, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+bucketColumns+` FROM buckets WHERE name = $1`, name)
	bucket, err := scanBucket(row)
	if err != nil {
		return Bucket{}, classify(err)
	}
	return bucket, nil
}

// ListBuckets returns one page of buckets ordered by name plus the cursor of the
// following page (empty when the page is the last).
func (s *Store) ListBuckets(ctx context.Context, f BucketFilter) ([]Bucket, string, error) {
	limit := clampLimit(f.Limit)
	scope := fmt.Sprintf("buckets|%s|%s|%s|%s", f.OwnerID, f.OwnerKind, f.TeamID, f.NamePrefix)
	cursor, err := decodeCursor(scope, f.Cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+bucketColumns+` FROM buckets
		WHERE ($1::text = '' OR owner_id = $1::text)
		  AND ($2::text = '' OR owner_kind = $2::text)
		  AND ($3::text = '' OR team_id = $3::text)
		  AND ($4::text = '' OR starts_with(name, $4::text))
		  AND ($5::text = '' OR name > $5::text)
		ORDER BY name
		LIMIT $6`, f.OwnerID, f.OwnerKind, f.TeamID, f.NamePrefix, cursor, limit+1)
	if err != nil {
		return nil, "", classify(err)
	}
	items, err := scanRows(rows, scanBucket)
	if err != nil {
		return nil, "", err
	}
	page, next := paginate(items, limit, scope, func(b Bucket) string { return b.Name })
	return page, next, nil
}

// UpdateBucket rewrites the mutable bucket attributes: the owner, the team
// scope, the description and the quotas. Name, id and the usage counters are
// immutable here.
func (s *Store) UpdateBucket(ctx context.Context, b Bucket) (Bucket, error) {
	if b.OwnerKind == "" {
		return Bucket{}, errors.New("bucket owner kind is required")
	}
	row := s.pool.QueryRow(ctx, `UPDATE buckets
		SET owner_id = $2, owner_kind = $3, team_id = $4, description = $5,
			quota_bytes = $6, quota_objects = $7, updated_at = now()
		WHERE id = $1
		RETURNING `+bucketColumns,
		b.ID, b.OwnerID, b.OwnerKind, b.TeamID, b.Description, b.QuotaBytes, b.QuotaObjects)
	out, err := scanBucket(row)
	if err != nil {
		return Bucket{}, classify(err)
	}
	return out, nil
}

// DeleteBucket removes an empty bucket.
func (s *Store) DeleteBucket(ctx context.Context, id string) error {
	return s.withTx(ctx, func(tx txQuerier) error {
		var currentID string
		if err := tx.QueryRow(ctx, `SELECT id FROM buckets WHERE id = $1 FOR UPDATE`, id).Scan(&currentID); err != nil {
			return classify(err)
		}
		var objects int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM objects WHERE bucket_id = $1`, id).Scan(&objects); err != nil {
			return classify(err)
		}
		if objects > 0 {
			return withSentinel(ErrBucketNotEmpty, fmt.Errorf("bucket %s still holds %d objects", id, objects))
		}
		if _, err := tx.Exec(ctx, `DELETE FROM buckets WHERE id = $1`, id); err != nil {
			return classify(err)
		}
		return nil
	})
}
