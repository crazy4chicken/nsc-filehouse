package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// GetQuota returns the quota of a subject. The boolean reports existence; a
// missing quota means unlimited.
func (s *Store) GetQuota(ctx context.Context, kind, id string) (Quota, bool, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+quotaColumns+` FROM quotas WHERE subject_kind = $1 AND subject_id = $2`, kind, id)
	quota, err := scanQuota(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Quota{}, false, nil
		}
		return Quota{}, false, classify(err)
	}
	return quota, true, nil
}

// PutQuota upserts a subject quota. Zero limits mean unlimited.
func (s *Store) PutQuota(ctx context.Context, q Quota) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO quotas (subject_kind, subject_id, max_bytes, max_objects)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (subject_kind, subject_id) DO UPDATE SET
			max_bytes = excluded.max_bytes, max_objects = excluded.max_objects, updated_at = now()`,
		q.SubjectKind, q.SubjectID, q.MaxBytes, q.MaxObjects)
	return classify(err)
}

// ListQuotas returns one page of quotas ordered by subject kind and id plus the
// cursor of the following page. An empty kind matches every kind; a malformed or
// foreign cursor yields ErrInvalidCursor.
func (s *Store) ListQuotas(ctx context.Context, kind, cursor string, limit int) ([]Quota, string, error) {
	pageSize := clampLimit(limit)
	scope := "quotas|" + kind
	after, err := decodeCursor(scope, cursor)
	if err != nil {
		return nil, "", err
	}
	afterKind, afterID := splitQuotaCursor(after)
	rows, err := s.pool.Query(ctx, `SELECT `+quotaColumns+` FROM quotas
		WHERE ($1::text = '' OR subject_kind = $1::text)
		  AND ($2::text = '' OR (subject_kind, subject_id) > ($2::text, $3::text))
		ORDER BY subject_kind, subject_id
		LIMIT $4`, kind, afterKind, afterID, pageSize+1)
	if err != nil {
		return nil, "", classify(err)
	}
	items, err := scanRows(rows, scanQuota)
	if err != nil {
		return nil, "", err
	}
	page, next := paginate(items, pageSize, scope, func(q Quota) string { return q.SubjectKind + quotaCursorSeparator + q.SubjectID })
	return page, next, nil
}

// quotaCursorSeparator joins the two cursor components; it cannot appear in a
// subject kind or id.
const quotaCursorSeparator = "\x1f"

func splitQuotaCursor(value string) (string, string) {
	if kind, id, ok := strings.Cut(value, quotaCursorSeparator); ok {
		return kind, id
	}
	return "", value
}
