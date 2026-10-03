package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Column lists shared by queries and scans so selects and scans cannot drift.
const (
	bucketColumns      = `id, name, owner_id, owner_kind, team_id, description, quota_bytes, quota_objects, used_bytes, used_objects, created_at, updated_at`
	objectColumns      = `bucket_id, key, blob_hash, size, etag, content_type, owner_id, metadata::text, created_at, updated_at`
	uploadColumns      = `id, bucket_id, key, owner_id, content_type, metadata::text, declared_size, part_count, created_at, expires_at`
	uploadPartColumns  = `upload_id, part_no, size, sha256, created_at`
	quotaColumns       = `subject_kind, subject_id, max_bytes, max_objects, updated_at`
	idempotencyColumns = `scope, key, fingerprint, status, response, created_at`
)

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// Bucket is a namespace owning objects.
type Bucket struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	OwnerID      string    `json:"owner_id"`
	OwnerKind    string    `json:"owner_kind"`
	TeamID       string    `json:"team_id"`
	Description  string    `json:"description"`
	QuotaBytes   int64     `json:"quota_bytes"`
	QuotaObjects int64     `json:"quota_objects"`
	UsedBytes    int64     `json:"used_bytes"`
	UsedObjects  int64     `json:"used_objects"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Object is a stored object; ETag holds the quoted lowercase sha256 of the bytes
// and BlobHash the bare digest.
type Object struct {
	BucketID    string            `json:"bucket_id"`
	Key         string            `json:"key"`
	BlobHash    string            `json:"blob_hash"`
	Size        int64             `json:"size"`
	ETag        string            `json:"etag"`
	ContentType string            `json:"content_type"`
	OwnerID     string            `json:"owner_id"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Blob is a content addressed blob row.
type Blob struct {
	Hash       string    `json:"hash"`
	Size       int64     `json:"size"`
	Refcount   int64     `json:"refcount"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// Upload is an in progress multipart upload.
type Upload struct {
	ID           string            `json:"id"`
	BucketID     string            `json:"bucket_id"`
	Key          string            `json:"key"`
	OwnerID      string            `json:"owner_id"`
	ContentType  string            `json:"content_type"`
	Metadata     map[string]string `json:"metadata"`
	DeclaredSize int64             `json:"declared_size"`
	PartCount    int               `json:"part_count"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
}

// UploadPart is one staged part of a multipart upload.
type UploadPart struct {
	UploadID  string    `json:"upload_id"`
	PartNo    int       `json:"part_no"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Quota is a per subject limit; zero means unlimited.
type Quota struct {
	SubjectKind string    `json:"subject_kind"`
	SubjectID   string    `json:"subject_id"`
	MaxBytes    int64     `json:"max_bytes"`
	MaxObjects  int64     `json:"max_objects"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// QuotaLimit bounds the aggregate usage of a subject. The zero value is
// unlimited; a single zero field leaves that dimension unbounded.
type QuotaLimit struct {
	MaxBytes   int64
	MaxObjects int64
}

// Unlimited reports whether the limit bounds nothing at all.
func (q QuotaLimit) Unlimited() bool {
	return q.MaxBytes <= 0 && q.MaxObjects <= 0
}

// IdempotencyRecord stores a replayable response for an Idempotency-Key.
type IdempotencyRecord struct {
	Scope       string    `json:"scope"`
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	Status      int       `json:"status"`
	Response    []byte    `json:"response"`
	CreatedAt   time.Time `json:"created_at"`
}

// UsageRow reports the usage of one bucket plus the subject level quota.
type UsageRow struct {
	BucketID          string `json:"bucket_id"`
	BucketName        string `json:"bucket_name"`
	OwnerID           string `json:"owner_id"`
	OwnerKind         string `json:"owner_kind"`
	TeamID            string `json:"team_id"`
	UsedBytes         int64  `json:"used_bytes"`
	UsedObjects       int64  `json:"used_objects"`
	QuotaBytes        int64  `json:"quota_bytes"`
	QuotaObjects      int64  `json:"quota_objects"`
	SubjectMaxBytes   int64  `json:"subject_max_bytes"`
	SubjectMaxObjects int64  `json:"subject_max_objects"`
}

// Stats reports platform wide totals.
type Stats struct {
	Buckets        int64 `json:"buckets"`
	Objects        int64 `json:"objects"`
	LogicalBytes   int64 `json:"logical_bytes"`
	Blobs          int64 `json:"blobs"`
	BlobBytes      int64 `json:"blob_bytes"`
	ZeroRefBlobs   int64 `json:"zero_ref_blobs"`
	Uploads        int64 `json:"uploads"`
	ExpiredUploads int64 `json:"expired_uploads"`
	Quotas         int64 `json:"quotas"`
}

func scanBucket(row rowScanner) (Bucket, error) {
	var b Bucket
	err := row.Scan(&b.ID, &b.Name, &b.OwnerID, &b.OwnerKind, &b.TeamID, &b.Description,
		&b.QuotaBytes, &b.QuotaObjects, &b.UsedBytes, &b.UsedObjects, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func scanObject(row rowScanner) (Object, error) {
	var (
		o        Object
		metadata string
	)
	if err := row.Scan(&o.BucketID, &o.Key, &o.BlobHash, &o.Size, &o.ETag, &o.ContentType,
		&o.OwnerID, &metadata, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return Object{}, err
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &o.Metadata); err != nil {
			return Object{}, fmt.Errorf("decode object metadata: %w", err)
		}
	}
	if o.Metadata == nil {
		o.Metadata = map[string]string{}
	}
	return o, nil
}

func scanUpload(row rowScanner) (Upload, error) {
	var (
		u        Upload
		metadata string
		parts    int32
	)
	if err := row.Scan(&u.ID, &u.BucketID, &u.Key, &u.OwnerID, &u.ContentType, &metadata,
		&u.DeclaredSize, &parts, &u.CreatedAt, &u.ExpiresAt); err != nil {
		return Upload{}, err
	}
	u.PartCount = int(parts)
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &u.Metadata); err != nil {
			return Upload{}, fmt.Errorf("decode upload metadata: %w", err)
		}
	}
	if u.Metadata == nil {
		u.Metadata = map[string]string{}
	}
	return u, nil
}

func scanUploadPart(row rowScanner) (UploadPart, error) {
	var (
		p      UploadPart
		partNo int32
	)
	if err := row.Scan(&p.UploadID, &partNo, &p.Size, &p.SHA256, &p.CreatedAt); err != nil {
		return UploadPart{}, err
	}
	p.PartNo = int(partNo)
	return p, nil
}

func scanQuota(row rowScanner) (Quota, error) {
	var q Quota
	err := row.Scan(&q.SubjectKind, &q.SubjectID, &q.MaxBytes, &q.MaxObjects, &q.UpdatedAt)
	return q, err
}

func scanIdempotency(row rowScanner) (IdempotencyRecord, error) {
	var r IdempotencyRecord
	err := row.Scan(&r.Scope, &r.Key, &r.Fingerprint, &r.Status, &r.Response, &r.CreatedAt)
	return r, err
}

func scanRows[T any](rows pgx.Rows, scan func(rowScanner) (T, error)) ([]T, error) {
	defer rows.Close()
	out := make([]T, 0, 8)
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, classify(err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, classify(err)
	}
	return out, nil
}
