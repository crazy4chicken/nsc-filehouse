package store

import (
	"context"
	"fmt"
	"time"

	"github.com/crazy4chicken/nsc-filehouse/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// migrationLockKey is the PostgreSQL advisory lock key ("nscfilew" in ASCII)
// serialising migrations across processes.
const migrationLockKey int64 = 0x6e736366696c6577

// Migrate applies every pending goose migration from the embedded FS behind a
// PostgreSQL advisory lock and returns the resulting schema version. It is
// idempotent: a second call applies nothing and logs "no pending migrations".
func (s *Store) Migrate(ctx context.Context) (int64, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return 0, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, migrationLockKey); err != nil {
			s.log.Warn("release migration lock", "error", err)
		}
	}()

	// Everything this service owns lives in the fixed filehouse schema, so it
	// must exist before goose creates its version table there.
	if err := ensureSchema(ctx, conn); err != nil {
		return 0, err
	}

	// Closing the sql.DB does not close the pool it was opened from.
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSlog(s.log))
	if err != nil {
		return 0, fmt.Errorf("init migrations: %w", err)
	}
	applied, err := provider.Up(ctx)
	if err != nil {
		return 0, fmt.Errorf("apply migrations: %w", err)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("read migration version: %w", err)
	}
	if len(applied) == 0 {
		s.log.Info("no pending migrations", "version", version)
		return version, nil
	}
	versions := make([]int64, 0, len(applied))
	for _, result := range applied {
		versions = append(versions, result.Source.Version)
	}
	s.log.Info("migrations applied", "count", len(applied), "versions", versions, "version", version)
	return version, nil
}

// ensureSchema creates the filehouse schema when it is missing. It refuses a
// database whose previous migrations ran in public: adopting it here would
// silently point the service at an empty schema while every existing bucket,
// object and blob row stays stranded behind it.
func ensureSchema(ctx context.Context, conn *pgxpool.Conn) error {
	var legacy bool
	err := conn.QueryRow(ctx, `SELECT to_regclass($1) IS NULL AND to_regclass($2) IS NOT NULL`,
		Schema+".goose_db_version", "public.goose_db_version").Scan(&legacy)
	if err != nil {
		return fmt.Errorf("inspect schema state: %w", err)
	}
	if legacy {
		return fmt.Errorf("legacy migrations found in the public schema: move the tables into %s (ALTER TABLE public.<table> SET SCHEMA %s) or start from an empty database", Schema, Schema)
	}
	if _, err := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+Schema); err != nil {
		return fmt.Errorf("create schema %s: %w", Schema, err)
	}
	return nil
}
