package test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/presign"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// envTestDatabase gates the integration suite. When it is unset every test in
// this package skips, so `go test ./test/...` stays green on machines without
// PostgreSQL.
const envTestDatabase = "FILEHOUSE_TEST_PG"

// suite holds the process-wide dependencies shared by every test. Each test
// rebuilds the fixture IAM server and the HTTP server but reuses the database
// pool, the blob directory and the presign key.
type suite struct {
	store   *store.Store
	blobs   *blob.Store
	pool    *pgxpool.Pool
	signer  *presign.Signer
	cfg     *config.Config
	logger  *slog.Logger
	rootDir string
}

var testSuite *suite

// TestMain opens PostgreSQL, applies migrations and prepares the shared test
// dependencies once. A missing FILEHOUSE_TEST_PG is not an error: the
// tests skip themselves.
func TestMain(m *testing.M) {
	dsn := os.Getenv(envTestDatabase)
	if dsn == "" {
		os.Exit(m.Run())
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	metadata, err := store.Open(ctx, dsn, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: open store: %v\n", err)
		os.Exit(1)
	}
	if _, err := metadata.Migrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: migrate: %v\n", err)
		metadata.Close()
		os.Exit(1)
	}
	rootDir, err := os.MkdirTemp("", "filehouse-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: temp dir: %v\n", err)
		metadata.Close()
		os.Exit(1)
	}
	blobs, err := blob.Open(rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: open blobs: %v\n", err)
		metadata.Close()
		os.RemoveAll(rootDir)
		os.Exit(1)
	}
	signer, err := presign.Load(filepath.Join(rootDir, "keys"), time.Hour)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: load signer: %v\n", err)
		metadata.Close()
		os.RemoveAll(rootDir)
		os.Exit(1)
	}
	poolConfig, err := store.PoolConfig(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: parse pool config: %v\n", err)
		metadata.Close()
		os.RemoveAll(rootDir)
		os.Exit(1)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: open pool: %v\n", err)
		metadata.Close()
		os.RemoveAll(rootDir)
		os.Exit(1)
	}

	testSuite = &suite{
		store:   metadata,
		blobs:   blobs,
		pool:    pool,
		signer:  signer,
		cfg:     testConfig(rootDir),
		logger:  logger,
		rootDir: rootDir,
	}

	code := m.Run()

	pool.Close()
	metadata.Close()
	os.RemoveAll(rootDir)
	os.Exit(code)
}

// testConfig builds a configuration suited to the integration tests: small
// limits keep payloads tiny, quotas stay unlimited unless a test sets them and
// the public base URL is derived from the request.
func testConfig(rootDir string) *config.Config {
	return &config.Config{
		ListenAddress: "127.0.0.1",
		BlobDir:       rootDir,
		KeyDir:        filepath.Join(rootDir, "keys"),
		LogLevel:      "error",
		NodeID:        "integration-test",
		IAM: config.IAMConfig{
			Timeout: 5 * time.Second,
		},
		Presign: config.PresignConfig{
			DefaultTTL: 15 * time.Minute,
			MaxTTL:     time.Hour,
		},
		Limits: config.LimitsConfig{
			ObjectMaxBytes:            32 << 20,
			PartMaxBytes:              8 << 20,
			UploadTTL:                 time.Hour,
			BucketDefaultQuotaBytes:   0,
			BucketDefaultQuotaObjects: 0,
		},
		GC: config.GCConfig{
			Interval: time.Hour,
			Grace:    0,
		},
		IdempotencyTTL: time.Hour,
	}
}

// requireSuite skips the calling test when FILEHOUSE_TEST_PG is unset.
func requireSuite(t *testing.T) *suite {
	t.Helper()
	if testSuite == nil {
		t.Skipf("%s is not set; skipping integration test", envTestDatabase)
	}
	return testSuite
}
