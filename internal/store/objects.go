package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PutObjectRequest describes an object write. Replace allows overwriting an
// existing key; without it an existing key yields ErrConflict.
//
// OwnerQuota and TeamQuota are enforced atomically with the write against the
// aggregate usage of the object owner and of the bucket team. The caller
// resolves them from the quotas table; the zero value means unlimited.
type PutObjectRequest struct {
	BucketID    string
	Key         string
	BlobHash    string
	ContentType string
	OwnerID     string
	Size        int64
	Metadata    map[string]string
	Replace     bool
	OwnerQuota  QuotaLimit
	TeamQuota   QuotaLimit
}

const defaultContentType = "application/octet-stream"

// PutObject stores object metadata inside one transaction: the bucket row is
// locked, quotas are checked, counters and the blob refcount move with the
// object row.
func (s *Store) PutObject(ctx context.Context, req PutObjectRequest) (Object, error) {
	contentType := req.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	var out Object
	err := s.withTx(ctx, func(tx txQuerier) error {
		var (
			bucketOwnerID, bucketTeamID                      string
			quotaBytes, quotaObjects, usedBytes, usedObjects int64
		)
		if err := tx.QueryRow(ctx, `SELECT owner_id, team_id, quota_bytes, quota_objects, used_bytes, used_objects
			FROM buckets WHERE id = $1 FOR UPDATE`, req.BucketID).
			Scan(&bucketOwnerID, &bucketTeamID, &quotaBytes, &quotaObjects, &usedBytes, &usedObjects); err != nil {
			return classify(err)
		}

		var (
			previousHash string
			previousSize int64
			exists       bool
		)
		err := tx.QueryRow(ctx, `SELECT blob_hash, size FROM objects WHERE bucket_id = $1 AND key = $2`,
			req.BucketID, req.Key).Scan(&previousHash, &previousSize)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			exists = false
		case err != nil:
			return classify(err)
		default:
			exists = true
		}
		if exists && !req.Replace {
			return withSentinel(ErrConflict, fmt.Errorf("object %s/%s already exists", req.BucketID, req.Key))
		}

		deltaBytes := req.Size
		deltaObjects := int64(1)
		if exists {
			deltaBytes = req.Size - previousSize
			deltaObjects = 0
		}

		// Subject quotas project the caller supplied bounds onto the aggregate
		// counters of every bucket of that subject. The advisory lock serialises
		// concurrent writers of the same subject for the rest of the
		// transaction, so the projection cannot be overtaken.
		if !req.OwnerQuota.Unlimited() {
			if err := lockQuotaSubject(ctx, tx, "filehouse:quota:user:"+req.OwnerID); err != nil {
				return err
			}
			ownerBytes, ownerObjects, err := quotaSubjectUsage(ctx, tx,
				`SELECT COALESCE(sum(used_bytes), 0), COALESCE(sum(used_objects), 0) FROM buckets WHERE owner_id = $1`,
				req.OwnerID)
			if err != nil {
				return err
			}
			// A replaced object only reduces the projection when its bucket is
			// owned by the same subject; otherwise its previous bytes were
			// counted against the bucket owner.
			ownerDeltaBytes := req.Size
			if exists && bucketOwnerID == req.OwnerID {
				ownerDeltaBytes = deltaBytes
			}
			if req.OwnerQuota.MaxBytes > 0 && ownerBytes+ownerDeltaBytes > req.OwnerQuota.MaxBytes {
				return withSentinel(ErrQuotaExceeded, fmt.Errorf("owner %s byte quota %d exceeded", req.OwnerID, req.OwnerQuota.MaxBytes))
			}
			if req.OwnerQuota.MaxObjects > 0 && ownerObjects+deltaObjects > req.OwnerQuota.MaxObjects {
				return withSentinel(ErrQuotaExceeded, fmt.Errorf("owner %s object quota %d exceeded", req.OwnerID, req.OwnerQuota.MaxObjects))
			}
		}
		if !req.TeamQuota.Unlimited() && bucketTeamID != "" {
			if err := lockQuotaSubject(ctx, tx, "filehouse:quota:team:"+bucketTeamID); err != nil {
				return err
			}
			teamBytes, teamObjects, err := quotaSubjectUsage(ctx, tx,
				`SELECT COALESCE(sum(used_bytes), 0), COALESCE(sum(used_objects), 0) FROM buckets WHERE team_id = $1`,
				bucketTeamID)
			if err != nil {
				return err
			}
			if req.TeamQuota.MaxBytes > 0 && teamBytes+deltaBytes > req.TeamQuota.MaxBytes {
				return withSentinel(ErrQuotaExceeded, fmt.Errorf("team %s byte quota %d exceeded", bucketTeamID, req.TeamQuota.MaxBytes))
			}
			if req.TeamQuota.MaxObjects > 0 && teamObjects+deltaObjects > req.TeamQuota.MaxObjects {
				return withSentinel(ErrQuotaExceeded, fmt.Errorf("team %s object quota %d exceeded", bucketTeamID, req.TeamQuota.MaxObjects))
			}
		}

		if quotaBytes > 0 && usedBytes+deltaBytes > quotaBytes {
			return withSentinel(ErrQuotaExceeded, fmt.Errorf("bucket %s byte quota %d exceeded", req.BucketID, quotaBytes))
		}
		if quotaObjects > 0 && usedObjects+deltaObjects > quotaObjects {
			return withSentinel(ErrQuotaExceeded, fmt.Errorf("bucket %s object quota %d exceeded", req.BucketID, quotaObjects))
		}

		if !exists || previousHash != req.BlobHash {
			if _, err := tx.Exec(ctx, `INSERT INTO blobs (hash, size, refcount, last_seen_at)
				VALUES ($1, $2, 1, now())
				ON CONFLICT (hash) DO UPDATE SET refcount = blobs.refcount + 1, last_seen_at = now()`,
				req.BlobHash, req.Size); err != nil {
				return classify(err)
			}
			if exists {
				if _, err := tx.Exec(ctx, `UPDATE blobs SET refcount = GREATEST(refcount - 1, 0), last_seen_at = now()
					WHERE hash = $1`, previousHash); err != nil {
					return classify(err)
				}
			}
		} else if _, err := tx.Exec(ctx, `UPDATE blobs SET last_seen_at = now() WHERE hash = $1`, req.BlobHash); err != nil {
			return classify(err)
		}

		if _, err := tx.Exec(ctx, `UPDATE buckets
			SET used_bytes = used_bytes + $2, used_objects = used_objects + $3, updated_at = now()
			WHERE id = $1`, req.BucketID, deltaBytes, deltaObjects); err != nil {
			return classify(err)
		}

		row := tx.QueryRow(ctx, `INSERT INTO objects (bucket_id, key, blob_hash, size, etag, content_type, owner_id, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (bucket_id, key) DO UPDATE SET
				blob_hash = excluded.blob_hash,
				size = excluded.size,
				etag = excluded.etag,
				content_type = excluded.content_type,
				owner_id = excluded.owner_id,
				metadata = excluded.metadata,
				updated_at = now()
			RETURNING `+objectColumns,
			req.BucketID, req.Key, req.BlobHash, req.Size, quotedETag(req.BlobHash), contentType,
			req.OwnerID, emptyIfNil(req.Metadata))
		object, err := scanObject(row)
		if err != nil {
			return classify(err)
		}
		out = object
		return nil
	})
	if err != nil {
		return Object{}, err
	}
	return out, nil
}

// DeleteObject removes an object and returns it so the caller can release the
// underlying blob.
func (s *Store) DeleteObject(ctx context.Context, bucketID, key string) (Object, error) {
	var out Object
	err := s.withTx(ctx, func(tx txQuerier) error {
		var currentID string
		if err := tx.QueryRow(ctx, `SELECT id FROM buckets WHERE id = $1 FOR UPDATE`, bucketID).Scan(&currentID); err != nil {
			return classify(err)
		}
		row := tx.QueryRow(ctx, `SELECT `+objectColumns+` FROM objects WHERE bucket_id = $1 AND key = $2 FOR UPDATE`, bucketID, key)
		object, err := scanObject(row)
		if err != nil {
			return classify(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM objects WHERE bucket_id = $1 AND key = $2`, bucketID, key); err != nil {
			return classify(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE blobs SET refcount = GREATEST(refcount - 1, 0), last_seen_at = now()
			WHERE hash = $1`, object.BlobHash); err != nil {
			return classify(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE buckets
			SET used_bytes = GREATEST(used_bytes - $2, 0), used_objects = GREATEST(used_objects - 1, 0), updated_at = now()
			WHERE id = $1`, bucketID, object.Size); err != nil {
			return classify(err)
		}
		out = object
		return nil
	})
	if err != nil {
		return Object{}, err
	}
	return out, nil
}

// GetObject returns a single object.
func (s *Store) GetObject(ctx context.Context, bucketID, key string) (Object, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+objectColumns+` FROM objects WHERE bucket_id = $1 AND key = $2`, bucketID, key)
	object, err := scanObject(row)
	if err != nil {
		return Object{}, classify(err)
	}
	return object, nil
}

// ListObjects returns one page of objects ordered by key plus the cursor of the
// following page.
func (s *Store) ListObjects(ctx context.Context, bucketID, prefix, cursor string, limit int) ([]Object, string, error) {
	pageSize := clampLimit(limit)
	scope := fmt.Sprintf("objects|%s|%s", bucketID, prefix)
	after, err := decodeCursor(scope, cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+objectColumns+` FROM objects
		WHERE bucket_id = $1
		  AND starts_with(key, $2::text)
		  AND ($3::text = '' OR key > $3::text)
		ORDER BY key
		LIMIT $4`, bucketID, prefix, after, pageSize+1)
	if err != nil {
		return nil, "", classify(err)
	}
	items, err := scanRows(rows, scanObject)
	if err != nil {
		return nil, "", err
	}
	page, next := paginate(items, pageSize, scope, func(o Object) string { return o.Key })
	return page, next, nil
}

func quotedETag(hash string) string {
	return `"` + hash + `"`
}

// lockQuotaSubject serialises every writer of one quota subject for the rest of
// the transaction.
func lockQuotaSubject(ctx context.Context, tx txQuerier, key string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1::text)::bigint)`, key); err != nil {
		return classify(err)
	}
	return nil
}

// quotaSubjectUsage sums the logical counters of every bucket matching query.
func quotaSubjectUsage(ctx context.Context, tx txQuerier, query, subject string) (int64, int64, error) {
	var bytes, objects int64
	if err := tx.QueryRow(ctx, query, subject).Scan(&bytes, &objects); err != nil {
		return 0, 0, classify(err)
	}
	return bytes, objects, nil
}
