package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Status markers stored in idempotency.status.
const (
	// IdemStatusPending marks a request that is currently executing.
	IdemStatusPending = 0
	// IdemStatusDead marks a request whose response was not retained (client or
	// server errors), so the same key may be claimed again.
	IdemStatusDead = -1
)

// IdempotencyStore is the subset of Store used by the HTTP idempotency
// middleware.
type IdempotencyStore interface {
	// ClaimIdempotent atomically claims a key, reclaiming rows that are dead or
	// older than staleBefore. It reports whether this caller owns the key.
	ClaimIdempotent(ctx context.Context, scope, key, fingerprint string, staleBefore time.Time) (bool, error)
	// GetIdempotent returns a stored record; the boolean reports existence.
	GetIdempotent(ctx context.Context, scope, key string) (IdempotencyRecord, bool, error)
	// PutIdempotent upserts a record, storing the final response or the dead marker.
	PutIdempotent(ctx context.Context, r IdempotencyRecord) error
}

// GetIdempotent returns a stored idempotency record.
func (s *Store) GetIdempotent(ctx context.Context, scope, key string) (IdempotencyRecord, bool, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+idempotencyColumns+` FROM idempotency WHERE scope = $1 AND key = $2`, scope, key)
	record, err := scanIdempotency(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IdempotencyRecord{}, false, nil
		}
		return IdempotencyRecord{}, false, classify(err)
	}
	return record, true, nil
}

// PutIdempotent upserts an idempotency record.
func (s *Store) PutIdempotent(ctx context.Context, r IdempotencyRecord) error {
	response := r.Response
	if response == nil {
		response = []byte{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO idempotency (scope, key, fingerprint, status, response, created_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (scope, key) DO UPDATE SET
			fingerprint = excluded.fingerprint,
			status = excluded.status,
			response = excluded.response,
			created_at = now()`,
		r.Scope, r.Key, r.Fingerprint, r.Status, response)
	return classify(err)
}

// ClaimIdempotent atomically claims an idempotency key. A fresh key, a dead
// record or a record older than staleBefore can be claimed; pending and live
// records cannot.
func (s *Store) ClaimIdempotent(ctx context.Context, scope, key, fingerprint string, staleBefore time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO idempotency (scope, key, fingerprint, status, response)
		VALUES ($1, $2, $3, $4, '\x'::bytea)
		ON CONFLICT (scope, key) DO UPDATE SET
			fingerprint = excluded.fingerprint,
			status = excluded.status,
			response = '\x'::bytea,
			created_at = now()
		WHERE idempotency.status = $5 OR idempotency.created_at < $6`,
		scope, key, fingerprint, IdemStatusPending, IdemStatusDead, staleBefore)
	if err != nil {
		return false, classify(err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteExpiredIdempotent prunes records created before the given time and
// reports how many rows were removed.
func (s *Store) DeleteExpiredIdempotent(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM idempotency WHERE created_at < $1`, before)
	if err != nil {
		return 0, classify(err)
	}
	return tag.RowsAffected(), nil
}
