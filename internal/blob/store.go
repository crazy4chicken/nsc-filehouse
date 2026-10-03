// Package blob implements the local content addressed blob store: blobs live at
// <root>/blobs/<aa>/<bb>/<sha256> and are written atomically through
// <root>/tmp, multipart parts are staged under <root>/uploads/<id>/<partNo>.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors returned by the blob store.
var (
	// ErrNotFound reports a missing blob file.
	ErrNotFound = errors.New("blob not found")
	// ErrChecksumMismatch reports a caller supplied sha256 that does not match.
	ErrChecksumMismatch = errors.New("checksum mismatch")
	// ErrPartTooLarge reports a multipart part exceeding its size limit.
	ErrPartTooLarge = errors.New("part too large")
	// ErrUploadIncomplete reports a missing part or an empty part list.
	ErrUploadIncomplete = errors.New("upload incomplete")
)

const (
	blobsDirName   = "blobs"
	tmpDirName     = "tmp"
	uploadsDirName = "uploads"

	dirMode  = 0o755
	fileMode = 0o644

	defaultListLimit = 10000
)

// Store is a file system backed content addressed blob store.
type Store struct {
	root       string
	blobsDir   string
	tmpDir     string
	uploadsDir string
}

// Open prepares a blob store below root, creating the blobs, tmp and uploads
// directories when needed.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("blob root is required")
	}
	s := &Store{
		root:       root,
		blobsDir:   filepath.Join(root, blobsDirName),
		tmpDir:     filepath.Join(root, tmpDirName),
		uploadsDir: filepath.Join(root, uploadsDirName),
	}
	if err := s.Writable(); err != nil {
		return nil, err
	}
	return s, nil
}

// Root returns the configured root directory.
func (s *Store) Root() string {
	return s.root
}

// Put stores the content of r and returns its sha256, size and whether the blob
// already existed.
func (s *Store) Put(ctx context.Context, r io.Reader) (string, int64, bool, error) {
	return s.put(ctx, r, "")
}

// PutVerified stores the content of r and verifies it against expectSHA256.
func (s *Store) PutVerified(ctx context.Context, r io.Reader, expectSHA256 string) (string, int64, bool, error) {
	expected := strings.ToLower(strings.TrimSpace(expectSHA256))
	if expected != "" && !isHexDigest(expected) {
		return "", 0, false, fmt.Errorf("%w: malformed expected digest", ErrChecksumMismatch)
	}
	return s.put(ctx, r, expected)
}

func (s *Store) put(ctx context.Context, r io.Reader, expect string) (string, int64, bool, error) {
	tmp, err := os.CreateTemp(s.tmpDir, "incoming-*")
	if err != nil {
		return "", 0, false, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), &contextReader{ctx: ctx, r: r})
	if err != nil {
		discard()
		return "", 0, false, fmt.Errorf("write temp blob: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return "", 0, false, fmt.Errorf("sync temp blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		discard()
		return "", 0, false, fmt.Errorf("close temp blob: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	if expect != "" && expect != hash {
		_ = os.Remove(tmpPath)
		return hash, size, false, fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expect, hash)
	}
	deduped, err := s.commit(tmpPath, hash)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", 0, false, err
	}
	return hash, size, deduped, nil
}

// commit moves a fully written temp file into the content addressed layout. The
// temp file is always consumed.
func (s *Store) commit(tmpPath, hash string) (bool, error) {
	target := s.path(hash)
	switch _, err := os.Stat(target); {
	case err == nil:
		_ = os.Remove(tmpPath)
		return true, nil
	case !errors.Is(err, os.ErrNotExist):
		return false, fmt.Errorf("stat blob %s: %w", hash, err)
	}
	if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
		return false, fmt.Errorf("create blob directory: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return false, fmt.Errorf("commit blob %s: %w", hash, err)
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return false, err
	}
	return false, nil
}

// Open returns a reader for a stored blob.
func (s *Store) Open(hash string) (*os.File, error) {
	if !isHexDigest(hash) {
		return nil, ErrNotFound
	}
	file, err := os.Open(s.path(hash))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, hash)
		}
		return nil, err
	}
	return file, nil
}

// Stat returns the size of a stored blob.
func (s *Store) Stat(hash string) (int64, error) {
	if !isHexDigest(hash) {
		return 0, ErrNotFound
	}
	info, err := os.Stat(s.path(hash))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, hash)
		}
		return 0, err
	}
	return info.Size(), nil
}

// ModTime returns the modification time of a stored blob.
func (s *Store) ModTime(hash string) (time.Time, error) {
	if !isHexDigest(hash) {
		return time.Time{}, ErrNotFound
	}
	info, err := os.Stat(s.path(hash))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, fmt.Errorf("%w: %s", ErrNotFound, hash)
		}
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Remove deletes a stored blob file.
func (s *Store) Remove(hash string) error {
	if !isHexDigest(hash) {
		return ErrNotFound
	}
	if err := os.Remove(s.path(hash)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotFound, hash)
		}
		return err
	}
	return nil
}

// ListHashes walks the content addressed layout and calls fn for every stored
// blob, stopping after limit entries.
func (s *Store) ListHashes(ctx context.Context, limit int, fn func(string) error) error {
	return s.listHashes(ctx, "", limit, fn)
}

// ListHashesAfter walks the content addressed layout in hash order and calls fn
// for every stored blob that sorts after the given hash, stopping after limit
// entries. It lets a bounded sweep resume where an earlier one stopped: pass
// the last hash it saw, or "" to start at the beginning. A zero or negative
// limit falls back to defaultListLimit.
func (s *Store) ListHashesAfter(ctx context.Context, after string, limit int, fn func(string) error) error {
	return s.listHashes(ctx, after, limit, fn)
}

func (s *Store) listHashes(ctx context.Context, after string, limit int, fn func(string) error) error {
	if limit <= 0 {
		limit = defaultListLimit
	}
	top, err := os.ReadDir(s.blobsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	visited := 0
	for _, first := range top {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !first.IsDir() {
			continue
		}
		second, err := os.ReadDir(filepath.Join(s.blobsDir, first.Name()))
		if err != nil {
			return err
		}
		for _, leaf := range second {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !leaf.IsDir() {
				continue
			}
			files, err := os.ReadDir(filepath.Join(s.blobsDir, first.Name(), leaf.Name()))
			if err != nil {
				return err
			}
			for _, file := range files {
				if file.IsDir() || !isHexDigest(file.Name()) {
					continue
				}
				// The layout groups hashes by their first two byte pairs, so
				// the walk order is hash order; a plain comparison against
				// after resumes exactly after the file the caller last saw.
				if after != "" && file.Name() <= after {
					continue
				}
				if err := fn(file.Name()); err != nil {
					return err
				}
				visited++
				if visited >= limit {
					return nil
				}
			}
		}
	}
	return nil
}

// NewUpload prepares the staging directory of a multipart upload.
func (s *Store) NewUpload(id string) error {
	if err := validateUploadID(id); err != nil {
		return err
	}
	if err := os.MkdirAll(s.uploadDir(id), dirMode); err != nil {
		return fmt.Errorf("create upload directory: %w", err)
	}
	return nil
}

// PutPart streams one multipart part to staging and returns its size and sha256.
// maxBytes caps the part size; a value <= 0 means unlimited.
func (s *Store) PutPart(uploadID string, partNo int, r io.Reader, maxBytes int64) (int64, string, error) {
	if err := validateUploadID(uploadID); err != nil {
		return 0, "", err
	}
	if partNo < 1 {
		return 0, "", errors.New("part number must be >= 1")
	}
	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return 0, "", fmt.Errorf("create upload directory: %w", err)
	}
	path := filepath.Join(dir, strconv.Itoa(partNo))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
	if err != nil {
		return 0, "", fmt.Errorf("create part file: %w", err)
	}
	discard := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	source := r
	if maxBytes > 0 {
		source = io.LimitReader(r, maxBytes+1)
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hasher), source)
	if err != nil {
		discard()
		return 0, "", fmt.Errorf("write part: %w", err)
	}
	if maxBytes > 0 && size > maxBytes {
		discard()
		return 0, "", fmt.Errorf("%w: limit is %d bytes", ErrPartTooLarge, maxBytes)
	}
	if err := file.Sync(); err != nil {
		discard()
		return 0, "", fmt.Errorf("sync part: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return 0, "", fmt.Errorf("close part: %w", err)
	}
	return size, hex.EncodeToString(hasher.Sum(nil)), nil
}

// AssembleUpload concatenates the requested parts, in order, into the content
// addressed store.
func (s *Store) AssembleUpload(ctx context.Context, uploadID string, parts []int) (string, int64, bool, error) {
	if err := validateUploadID(uploadID); err != nil {
		return "", 0, false, err
	}
	if len(parts) == 0 {
		return "", 0, false, fmt.Errorf("%w: no parts requested", ErrUploadIncomplete)
	}
	dir := s.uploadDir(uploadID)
	tmp, err := os.CreateTemp(s.tmpDir, "assemble-*")
	if err != nil {
		return "", 0, false, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	hasher := sha256.New()
	writer := io.MultiWriter(tmp, hasher)
	var size int64
	for _, partNo := range parts {
		if err := ctx.Err(); err != nil {
			discard()
			return "", 0, false, err
		}
		if partNo < 1 {
			discard()
			return "", 0, false, errors.New("part number must be >= 1")
		}
		part, err := os.Open(filepath.Join(dir, strconv.Itoa(partNo)))
		if err != nil {
			discard()
			if errors.Is(err, os.ErrNotExist) {
				return "", 0, false, fmt.Errorf("%w: part %d is missing", ErrUploadIncomplete, partNo)
			}
			return "", 0, false, fmt.Errorf("open part %d: %w", partNo, err)
		}
		written, copyErr := io.Copy(writer, part)
		closeErr := part.Close()
		if copyErr != nil {
			discard()
			return "", 0, false, fmt.Errorf("read part %d: %w", partNo, copyErr)
		}
		if closeErr != nil {
			discard()
			return "", 0, false, fmt.Errorf("close part %d: %w", partNo, closeErr)
		}
		size += written
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return "", 0, false, fmt.Errorf("sync assembled blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		discard()
		return "", 0, false, fmt.Errorf("close assembled blob: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	deduped, err := s.commit(tmpPath, hash)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", 0, false, err
	}
	return hash, size, deduped, nil
}

// DropUpload removes the staging directory of an upload.
func (s *Store) DropUpload(uploadID string) error {
	if err := validateUploadID(uploadID); err != nil {
		return err
	}
	if err := os.RemoveAll(s.uploadDir(uploadID)); err != nil {
		return fmt.Errorf("drop upload %s: %w", uploadID, err)
	}
	return nil
}

// Writable verifies that the blob directories exist and accept writes.
func (s *Store) Writable() error {
	for _, dir := range []string{s.blobsDir, s.tmpDir, s.uploadsDir} {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	probe, err := os.CreateTemp(s.tmpDir, "writable-*")
	if err != nil {
		return fmt.Errorf("create probe file: %w", err)
	}
	path := probe.Name()
	if _, err := probe.Write([]byte("ok")); err != nil {
		_ = probe.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write probe file: %w", err)
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close probe file: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove probe file: %w", err)
	}
	return nil
}

func (s *Store) uploadDir(id string) string {
	return filepath.Join(s.uploadsDir, id)
}

func (s *Store) path(hash string) string {
	return filepath.Join(s.blobsDir, hash[0:2], hash[2:4], hash)
}

// syncDir flushes a directory entry. Windows cannot flush directory handles, so
// failures are ignored there.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory %s: %w", dir, err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}

func isHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := range len(value) {
		switch char := value[i]; {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		default:
			return false
		}
	}
	return true
}

func validateUploadID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("invalid upload id %q", id)
	}
	for i := range len(id) {
		switch char := id[i]; {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char == '-', char == '_':
		default:
			return fmt.Errorf("invalid upload id %q", id)
		}
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
