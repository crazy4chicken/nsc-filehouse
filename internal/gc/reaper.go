// Package gc reclaims unreferenced blobs, expired multipart uploads and stale
// idempotency records.
package gc

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/crazy4chicken/nsc-filewarehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filewarehouse/internal/store"
)

const (
	defaultInterval        = 15 * time.Minute
	batchSize              = 500
	maxPerPass             = 20000
	defaultOrphanScanLimit = 5000
	idempotencyRetention   = 24 * time.Hour
)

// Config controls the reaper cadence, the unreferenced blob grace period and
// the orphan scan page size. A non positive grace means unreferenced blobs are
// reclaimed immediately.
type Config struct {
	Interval time.Duration
	Grace    time.Duration
	// OrphanScanLimit bounds how many blob files one pass inspects for the
	// orphan sweep; a non positive value falls back to 5000. The next pass
	// resumes after the last file seen, so a directory larger than one page is
	// reconciled over consecutive passes.
	OrphanScanLimit int
}

// Report summarises a single reaper pass.
type Report struct {
	BlobsDeleted       int64 `json:"blobs_deleted"`
	BytesDeleted       int64 `json:"bytes_deleted"`
	UploadsDeleted     int64 `json:"uploads_deleted"`
	IdempotencyDeleted int64 `json:"idempotency_deleted"`
	OrphanFilesDeleted int64 `json:"orphan_files_deleted"`
	OrphanBytesDeleted int64 `json:"orphan_bytes_deleted"`
	Errors             int64 `json:"errors"`
}

// Reaper deletes unreferenced blobs, expired uploads and stale idempotency
// records.
type Reaper struct {
	store    *store.Store
	blobs    *blob.Store
	log      *slog.Logger
	interval time.Duration
	grace    time.Duration

	// orphanLimit is the orphan scan page size; orphanMu guards orphanCursor,
	// the hash the next orphan scan resumes after ("" starts at the top).
	orphanLimit  int
	orphanMu     sync.Mutex
	orphanCursor string
}

// New builds a reaper. A non positive interval falls back to 15 minutes.
func New(s *store.Store, b *blob.Store, log *slog.Logger, cfg Config) *Reaper {
	if log == nil {
		log = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	orphanLimit := cfg.OrphanScanLimit
	if orphanLimit <= 0 {
		orphanLimit = defaultOrphanScanLimit
	}
	return &Reaper{
		store:       s,
		blobs:       b,
		log:         log,
		interval:    interval,
		grace:       cfg.Grace,
		orphanLimit: orphanLimit,
	}
}

// Run reaps until ctx is cancelled, starting with an immediate pass.
func (r *Reaper) Run(ctx context.Context) {
	r.log.Info("gc reaper started", "interval", r.interval.String(), "grace", r.grace.String())
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		if _, err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("gc pass completed with errors", "error", err)
		}
		select {
		case <-ctx.Done():
			r.log.Info("gc reaper stopped")
			return
		case <-ticker.C:
		}
	}
}

// Once performs a single reaper pass. It stops early on cancellation and
// reports the first error while still completing every reachable step.
func (r *Reaper) Once(ctx context.Context) (Report, error) {
	now := time.Now()
	var report Report
	var firstErr error
	fail := func(err error, message string, args ...any) {
		report.Errors++
		if firstErr == nil {
			firstErr = err
		}
		r.log.Warn(message, append(args, "error", err)...)
	}

	// Blobs: the file goes first so that a crash leaves a row that the next
	// pass reconciles, never an orphan file.
	for processed := 0; processed < maxPerPass; {
		blobs, err := r.store.ZeroRefBlobs(ctx, now.Add(-r.grace), batchSize)
		if err != nil {
			fail(err, "list unreferenced blobs")
			break
		}
		if len(blobs) == 0 {
			break
		}
		for _, unreferenced := range blobs {
			if ctx.Err() != nil {
				return report, firstErr
			}
			if err := r.blobs.Remove(unreferenced.Hash); err != nil && !errors.Is(err, blob.ErrNotFound) {
				fail(err, "remove blob file", "hash", unreferenced.Hash)
				continue
			}
			deleted, err := r.store.DeleteBlob(ctx, unreferenced.Hash, 0)
			if err != nil {
				fail(err, "delete blob row", "hash", unreferenced.Hash)
				continue
			}
			if deleted {
				report.BlobsDeleted++
				report.BytesDeleted += unreferenced.Size
			}
		}
		processed += len(blobs)
	}

	// Orphan files: content written into the blob directory that no blobs row
	// ever referenced, e.g. an upload rejected by the quota enforcement or a
	// crash between the file write and the object commit. The grace window
	// protects in-flight uploads: a file whose modification time is newer than
	// the cut-off may still be about to be committed. The walk is bounded per
	// pass and resumes after the last file seen, so a directory larger than one
	// page is reconciled over consecutive passes; an exhausted walk wraps back
	// to the top.
	cutoff := now.Add(-r.grace)
	r.orphanMu.Lock()
	visited := 0
	lastSeen := ""
	scanErr := r.blobs.ListHashesAfter(ctx, r.orphanCursor, r.orphanLimit, func(hash string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		visited++
		lastSeen = hash
		modTime, err := r.blobs.ModTime(hash)
		if err != nil {
			if !errors.Is(err, blob.ErrNotFound) {
				fail(err, "stat blob file", "hash", hash)
			}
			return nil
		}
		if !modTime.Before(cutoff) {
			return nil
		}
		exists, err := r.store.BlobHashExists(ctx, hash)
		if err != nil {
			fail(err, "probe blob row", "hash", hash)
			return nil
		}
		if exists {
			return nil
		}
		size, err := r.blobs.Stat(hash)
		if err != nil {
			if !errors.Is(err, blob.ErrNotFound) {
				fail(err, "stat orphan blob file", "hash", hash)
			}
			return nil
		}
		if err := r.blobs.Remove(hash); err != nil {
			if !errors.Is(err, blob.ErrNotFound) {
				fail(err, "remove orphan blob file", "hash", hash)
			}
			return nil
		}
		report.OrphanFilesDeleted++
		report.OrphanBytesDeleted += size
		return nil
	})
	switch {
	case scanErr == nil && visited < r.orphanLimit:
		// The walk reached the end of the directory: start over next pass.
		r.orphanCursor = ""
	case lastSeen != "":
		// The page filled up (or the pass was cancelled): resume after the
		// last file this pass saw.
		r.orphanCursor = lastSeen
	}
	cursor := r.orphanCursor
	r.orphanMu.Unlock()
	if scanErr != nil && ctx.Err() == nil {
		fail(scanErr, "scan orphan blob files")
	}
	r.log.Debug("gc orphan scan advanced",
		"cursor", cursor, "visited", visited, "files_deleted", report.OrphanFilesDeleted)

	// Multipart uploads past their expiry.
	for processed := 0; processed < maxPerPass; {
		uploads, err := r.store.ExpiredUploads(ctx, now, batchSize)
		if err != nil {
			fail(err, "list expired uploads")
			break
		}
		if len(uploads) == 0 {
			break
		}
		for _, upload := range uploads {
			if ctx.Err() != nil {
				return report, firstErr
			}
			if err := r.blobs.DropUpload(upload.ID); err != nil {
				fail(err, "drop upload staging", "upload", upload.ID)
				continue
			}
			if err := r.store.DeleteUpload(ctx, upload.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				fail(err, "delete upload row", "upload", upload.ID)
				continue
			}
			report.UploadsDeleted++
		}
		processed += len(uploads)
	}

	// Idempotency records older than the retention window.
	pruned, err := r.store.DeleteExpiredIdempotent(ctx, now.Add(-idempotencyRetention))
	if err != nil {
		fail(err, "prune idempotency records")
	} else {
		report.IdempotencyDeleted = pruned
	}

	r.log.Info("gc pass complete",
		"blobs_deleted", report.BlobsDeleted,
		"bytes_deleted", report.BytesDeleted,
		"orphan_files_deleted", report.OrphanFilesDeleted,
		"orphan_bytes_deleted", report.OrphanBytesDeleted,
		"uploads_deleted", report.UploadsDeleted,
		"idempotency_deleted", report.IdempotencyDeleted,
		"errors", report.Errors)
	return report, firstErr
}
