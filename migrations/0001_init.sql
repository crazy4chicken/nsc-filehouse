-- +goose Up
CREATE TABLE buckets (
    id text PRIMARY KEY,
    name text UNIQUE NOT NULL,
    owner_id text NOT NULL,
    owner_kind text NOT NULL,
    team_id text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    quota_bytes bigint NOT NULL DEFAULT 0,
    quota_objects bigint NOT NULL DEFAULT 0,
    used_bytes bigint NOT NULL DEFAULT 0,
    used_objects bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX buckets_owner_id_idx ON buckets(owner_id);

CREATE INDEX buckets_team_id_idx ON buckets(team_id);

CREATE TABLE blobs (
    hash text PRIMARY KEY,
    size bigint NOT NULL,
    refcount bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE objects (
    bucket_id text NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    key text NOT NULL,
    blob_hash text NOT NULL REFERENCES blobs(hash),
    size bigint NOT NULL,
    etag text NOT NULL,
    content_type text NOT NULL DEFAULT 'application/octet-stream',
    owner_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_id, key)
);

CREATE INDEX objects_blob_hash_idx ON objects(blob_hash);

CREATE TABLE uploads (
    id text PRIMARY KEY,
    bucket_id text NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    key text NOT NULL,
    owner_id text NOT NULL,
    content_type text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}',
    declared_size bigint NOT NULL DEFAULT -1,
    part_count int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX uploads_expires_at_idx ON uploads(expires_at);

CREATE TABLE upload_parts (
    upload_id text NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    part_no int NOT NULL,
    size bigint NOT NULL,
    sha256 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_no)
);

CREATE TABLE quotas (
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    max_bytes bigint NOT NULL DEFAULT 0,
    max_objects bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_kind, subject_id)
);

CREATE TABLE idempotency (
    scope text NOT NULL,
    key text NOT NULL,
    fingerprint text NOT NULL,
    status int NOT NULL,
    response bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, key)
);

CREATE INDEX blobs_refcount_idx ON blobs(refcount) WHERE refcount = 0;

-- +goose Down
DROP TABLE IF EXISTS idempotency;
DROP TABLE IF EXISTS quotas;
DROP TABLE IF EXISTS upload_parts;
DROP TABLE IF EXISTS uploads;
DROP TABLE IF EXISTS objects;
DROP TABLE IF EXISTS blobs;
DROP TABLE IF EXISTS buckets;
