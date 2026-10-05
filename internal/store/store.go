// Package store owns every PostgreSQL interaction: connection pooling, goose
// migrations and the SQL behind buckets, objects, blobs, uploads, quotas and
// idempotency records.
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema is the PostgreSQL schema that owns every table, index and goose
// version row this service creates. It is fixed to the service name so that
// nothing depends on write access to public, which PostgreSQL 15 and newer
// grant only to the database owner.
const Schema = "filehouse"

// schemaSearchPath pins the session search_path: the filehouse schema first,
// public kept behind it so functions installed there (extensions, operators)
// stay reachable.
const schemaSearchPath = Schema + ",public"

// Store is a pgx backed metadata store.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// PoolConfig parses a DSN and applies the session settings every filehouse
// connection carries. A search_path a DSN may specify is overridden: the
// schema is fixed, never caller chosen.
func PoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "nsc-filehouse"
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaSearchPath
	return cfg, nil
}

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, dsn string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	cfg, err := PoolConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool, log: log}, nil
}

// Ping verifies that the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases every pooled connection.
func (s *Store) Close() {
	s.pool.Close()
}

// txQuerier is the subset of pgx.Tx used by store transactions.
type txQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// withTx runs fn inside a transaction, rolling back on error.
func (s *Store) withTx(ctx context.Context, fn func(tx txQuerier) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return classify(err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	if err := fn(tx); err != nil {
		return classify(err)
	}
	return classify(tx.Commit(ctx))
}

// paginate trims an over fetched page and returns the cursor of the next page.
func paginate[T any](items []T, limit int, scope string, keyOf func(T) string) ([]T, string) {
	if len(items) <= limit {
		return items, ""
	}
	page := items[:limit]
	return page, encodeCursor(scope, keyOf(page[len(page)-1]))
}

const cursorVersion = 1

// listCursor is the opaque pagination token. The scope binds a cursor to the
// exact query that produced it.
type listCursor struct {
	Version int    `json:"v"`
	Scope   string `json:"s"`
	Value   string `json:"c"`
}

func encodeCursor(scope, value string) string {
	payload, err := json.Marshal(listCursor{Version: cursorVersion, Scope: scope, Value: value})
	if err != nil {
		// The envelope only contains strings, marshalling cannot fail.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(scope, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("%w: not base64url", ErrInvalidCursor)
	}
	var cursor listCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return "", fmt.Errorf("%w: not a cursor envelope", ErrInvalidCursor)
	}
	if cursor.Version != cursorVersion {
		return "", fmt.Errorf("%w: unsupported version %d", ErrInvalidCursor, cursor.Version)
	}
	if cursor.Scope != scope {
		return "", fmt.Errorf("%w: cursor does not belong to this query", ErrInvalidCursor)
	}
	return cursor.Value, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func emptyIfNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
