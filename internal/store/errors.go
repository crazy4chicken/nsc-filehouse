package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel errors returned by every store method. They are errors.Is compatible
// and wrap the underlying driver error when one is the cause.
var (
	// ErrNotFound reports a missing bucket, object, upload or blob.
	ErrNotFound = errors.New("not found")
	// ErrConflict reports a uniqueness or state conflict (bucket name taken,
	// object already exists on a non replacing put).
	ErrConflict = errors.New("conflict")
	// ErrQuotaExceeded reports that a bucket quota would be exceeded.
	ErrQuotaExceeded = errors.New("quota exceeded")
	// ErrBucketNotEmpty reports a delete on a bucket that still holds objects.
	ErrBucketNotEmpty = errors.New("bucket not empty")
	// ErrInvalidCursor reports a malformed or foreign pagination cursor.
	ErrInvalidCursor = errors.New("invalid cursor")
	// ErrUploadExpired reports a multipart upload past its expires_at.
	ErrUploadExpired = errors.New("upload expired")
)

// PostgreSQL SQLSTATE codes handled by classify.
const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
	sqlstateCheckViolation      = "23514"
)

// withSentinel wraps err with a sentinel keeping both errors.Is targets.
func withSentinel(sentinel, err error) error {
	if err == nil {
		return sentinel
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

// classify maps driver errors onto the package sentinels: no rows becomes
// ErrNotFound, unique and check violations become ErrConflict, missing foreign
// keys become ErrNotFound.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return withSentinel(ErrNotFound, err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case sqlstateUniqueViolation, sqlstateCheckViolation:
			return withSentinel(ErrConflict, err)
		case sqlstateForeignKeyViolation:
			return withSentinel(ErrNotFound, err)
		}
	}
	return err
}
