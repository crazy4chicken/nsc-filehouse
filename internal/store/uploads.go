package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/crazy4chicken/nsc-filewarehouse/internal/id"
)

// CreateUpload registers a multipart upload. A missing id is generated.
func (s *Store) CreateUpload(ctx context.Context, u Upload) (Upload, error) {
	if u.ID == "" {
		u.ID = id.New()
	}
	if u.ExpiresAt.IsZero() {
		return Upload{}, errors.New("upload expires_at is required")
	}
	row := s.pool.QueryRow(ctx, `INSERT INTO uploads (id, bucket_id, key, owner_id, content_type, metadata, declared_size, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+uploadColumns,
		u.ID, u.BucketID, u.Key, u.OwnerID, u.ContentType, emptyIfNil(u.Metadata), u.DeclaredSize, u.ExpiresAt)
	out, err := scanUpload(row)
	if err != nil {
		return Upload{}, classify(err)
	}
	return out, nil
}

// GetUpload returns a multipart upload by id.
func (s *Store) GetUpload(ctx context.Context, id string) (Upload, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE id = $1`, id)
	upload, err := scanUpload(row)
	if err != nil {
		return Upload{}, classify(err)
	}
	return upload, nil
}

// PutUploadPart records a staged part, rejecting expired uploads with
// ErrUploadExpired.
func (s *Store) PutUploadPart(ctx context.Context, p UploadPart) (UploadPart, error) {
	if p.PartNo < 1 {
		return UploadPart{}, errors.New("part number must be >= 1")
	}
	var out UploadPart
	err := s.withTx(ctx, func(tx txQuerier) error {
		var expiresAt time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM uploads WHERE id = $1 FOR UPDATE`, p.UploadID).
			Scan(&expiresAt); err != nil {
			return classify(err)
		}
		if time.Now().After(expiresAt) {
			return withSentinel(ErrUploadExpired, fmt.Errorf("upload %s expired at %s", p.UploadID, expiresAt.UTC().Format(time.RFC3339)))
		}
		row := tx.QueryRow(ctx, `INSERT INTO upload_parts (upload_id, part_no, size, sha256)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (upload_id, part_no) DO UPDATE SET size = excluded.size, sha256 = excluded.sha256, created_at = now()
			RETURNING `+uploadPartColumns,
			p.UploadID, int32(p.PartNo), p.Size, p.SHA256)
		part, err := scanUploadPart(row)
		if err != nil {
			return classify(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE uploads SET part_count = GREATEST(part_count, $2) WHERE id = $1`,
			p.UploadID, int32(p.PartNo)); err != nil {
			return classify(err)
		}
		out = part
		return nil
	})
	if err != nil {
		return UploadPart{}, err
	}
	return out, nil
}

// ListUploadParts returns the staged parts of an upload ordered by part number.
func (s *Store) ListUploadParts(ctx context.Context, uploadID string) ([]UploadPart, error) {
	var exists string
	if err := s.pool.QueryRow(ctx, `SELECT id FROM uploads WHERE id = $1`, uploadID).Scan(&exists); err != nil {
		return nil, classify(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+uploadPartColumns+` FROM upload_parts WHERE upload_id = $1 ORDER BY part_no`, uploadID)
	if err != nil {
		return nil, classify(err)
	}
	return scanRows(rows, scanUploadPart)
}

// DeleteUpload removes an upload and its parts.
func (s *Store) DeleteUpload(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM uploads WHERE id = $1`, id)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return withSentinel(ErrNotFound, fmt.Errorf("upload %s not found", id))
	}
	return nil
}

// ExpiredUploads lists uploads past their expiry, oldest first.
func (s *Store) ExpiredUploads(ctx context.Context, now time.Time, limit int) ([]Upload, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE expires_at < $1 ORDER BY expires_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, classify(err)
	}
	return scanRows(rows, scanUpload)
}
