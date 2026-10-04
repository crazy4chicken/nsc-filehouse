---
title: Uploads and downloads
outline: 2
---

# Uploads and downloads

`nsc-filehouse` stores object bytes in a content-addressed local directory and
the object metadata (owner, size, content type, tags, SHA-256) in PostgreSQL.
This page covers the object model, the three write paths — direct PUT, multipart
upload and presigned PUT — and how reads behave. Route-level details live in the
[API reference](/api/reference/objects); the [Uploads](/api/reference/uploads) and
[Presign](/api/reference/presign) pages document the transfer endpoints.

## Buckets and objects

A bucket is the unit of ownership, quota and permission: it belongs to a user or
to a team, and every object lives in exactly one bucket. Objects are addressed by
`bucket` + `key`; the key is byte-preserved with no normalization (percent-escapes
are decoded exactly once).

| Constraint | Rule |
| --- | --- |
| Bucket name | `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$` — 3–63 characters, must start and end alphanumeric. |
| Object key | 1–1024 bytes; no leading `/`; no empty segment (`//`), no `.`/`..` segments; no control characters (`0x00`–`0x1F`, `0x7F`). |
| Metadata name | Up to 64 characters from the HTTP token set (the `X-Filehouse-Meta-<Name>` suffix). |
| Metadata size | `name + value` at most 2048 bytes per entry; values must be printable. |

List the objects of a bucket with `GET /api/v1/buckets/{bucket}/objects`:
`prefix` filters by key prefix, and `limit` (default 100, maximum 1000) plus the
opaque `cursor` page through results in ascending key order. Pass `next_cursor`
back verbatim; an empty `next_cursor` marks the last page.

## Direct upload

```
PUT /api/v1/buckets/{bucket}/objects/{key}
```

The body is the raw object bytes. Three request headers shape the stored object:

| Header | Effect |
| --- | --- |
| `Content-Type` | Stored content type. Empty or absent defaults to `application/octet-stream`. |
| `X-Filehouse-SHA256` | Optional expected digest: bare hexadecimal SHA-256 (case-insensitive, 64 characters). A malformed value or a mismatch with the received bytes fails the request with `422 checksum_mismatch` — the object is not stored. |
| `X-Filehouse-Meta-<Name>` | Zero or more custom metadata entries. The stored name is the canonicalized suffix after the prefix; repeated headers keep the last value. Echoed back on every read. |

The body is capped by `FILEHOUSE_OBJECT_MAX_BYTES` (default 5 GiB). A
`Content-Length` above the cap is rejected immediately and the stream is also
bounded while it is consumed, so both answers are `413 payload_too_large`.

```sh
SHA=$(sha256sum report.pdf | cut -d' ' -f1)
curl -sS -X PUT "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/pdf' \
  -H "X-Filehouse-SHA256: $SHA" \
  -H 'X-Filehouse-Meta-Project: board-deck' \
  --data-binary @report.pdf
```

A successful upload is always `201` — including when it replaces an existing key
— and returns the object row plus the headers `ETag: "<sha256>"` and
`X-Filehouse-SHA256: <sha256>`. Other outcomes: `400 invalid_key` /
`invalid_request`, `403 insufficient_permissions`, `404 bucket_not_found`,
`413 payload_too_large` / `413 quota_exceeded`, `422 checksum_mismatch`.

## Multipart uploads

Use multipart when a single PUT is impractical — very large objects, parallel
part transfers, or resumable progress. The flow is initiate → upload parts →
complete (or abort). Parts are staged server-side and assembled at completion
through the same quota and dedup path as a direct PUT.

### 1. Initiate

```sh
UPLOAD_ID=$(curl -sS -X POST "$BASE/api/v1/buckets/archive/uploads" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"2026/backup.tar","content_type":"application/x-tar","size":734003200}' \
  | jq -r .upload_id)
```

The response is `201` with `upload_id`, `expires_at` and `part_count` (`0` at
creation). `key` is required; `content_type` defaults to
`application/octet-stream`; `metadata` takes the same entries as
`X-Filehouse-Meta-*`; `size` is an optional declared total used for authorization
attributes only (negative → `400 invalid_request`). The upload expires after
`FILEHOUSE_UPLOAD_TTL` (default 24h); any use after `expires_at` answers
`410 upload_expired`.

### 2. Upload the parts

```sh
curl -sS -X PUT "$BASE/api/v1/buckets/archive/uploads/$UPLOAD_ID/parts/1" \
  -H "Authorization: Bearer $TOKEN" --data-binary @part-1
```

Each part is raw bytes (`--data-binary`, never a multipart/form-data envelope).
The response is `200` with `upload_id`, `part_no`, `size`, `sha256` and
`created_at`.

| Rule | Value |
| --- | --- |
| Part number | Integer `>= 1`. Numbers need not be contiguous, but the completion list must be strictly increasing. |
| Part size | `FILEHOUSE_PART_MAX_BYTES` (default 256 MiB); `0` disables the cap. Over the cap → `413 payload_too_large`. |
| Minimum part size | None; zero-byte parts are accepted. |
| Re-upload | Re-PUT of the same part number overwrites the staged part. |
| Staging | Parts stay in the upload's staging area until completion or expiry. |

Inspect an upload with `GET /api/v1/buckets/{bucket}/uploads/{uploadID}`: it
returns the metadata, `declared_size` (`-1` when unknown), `parts`, and
`part_count` — the highest part number seen so far, not a count of parts.

### 3. Complete

```sh
curl -sS -X POST "$BASE/api/v1/buckets/archive/uploads/$UPLOAD_ID/complete" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"parts":[{"part_no":1,"sha256":"<sha256 of part 1>"},{"part_no":2}]}'
```

The server validates the list against the staged parts before assembling:
`part_no` must be `>= 1` and strictly increasing, the list length must equal the
number of staged parts (and be non-empty), each `part_no` must match the staged
sequence, and an optional `sha256` must match case-insensitively. Any mismatch is
`422 part_mismatch`. `sha256` values in the request are optional — omit them to
skip the per-part check.

Completion returns `201` with the object row and the `ETag` /
`X-Filehouse-SHA256` headers, then deletes the upload row and its staging area.
The assembled size is what gets quota-checked (`413 quota_exceeded`), not the
declared `size`.

### 4. Abort

```sh
curl -sS -X DELETE "$BASE/api/v1/buckets/archive/uploads/$UPLOAD_ID" \
  -H "Authorization: Bearer $TOKEN"
```

`204` on success; the staged parts are removed and the upload identifier becomes
unusable. An expired upload answers `410 upload_expired` here as well.

Uploads are private to their owner: inspecting, completing, aborting or writing
parts of someone else's upload additionally requires the `:any` scope of the
operation verb (`read` for inspection, `write` for the rest). The POST endpoints
accept `Idempotency-Key`, so a retried initiate or complete is replayed instead
of duplicating work.

## Presigned URLs

A presigned URL is a bearer credential for one object and one method. Mint it
with an authenticated request:

```sh
curl -sS -X POST "$BASE/api/v1/presign" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"bucket":"reports","key":"2026/report.pdf","method":"GET","ttl_seconds":600}'
```

The response contains `url`, `method` (upper-cased), `bucket` (canonical name),
`key` and `expires_at`.

| Field | Rule |
| --- | --- |
| `method` | `GET`, `HEAD` or `PUT` only. |
| `ttl_seconds` | Absent or `0` uses `FILEHOUSE_PRESIGN_DEFAULT_TTL` (default 15m); negative or above `FILEHOUSE_PRESIGN_MAX_TTL` (default 24h) → `400 invalid_request`. The expiry is stored in whole seconds, so a link never lives longer than requested. |
| `content_type` | PUT links only; at most 255 bytes with no control characters. Overrides the `Content-Type` a PUT redemption would otherwise use. |
| `max_bytes` | PUT links only: caps the redemption body. Positive values are clamped to `FILEHOUSE_OBJECT_MAX_BYTES`; `0` means no token-level cap; negative → `400 invalid_request`. |

Minting requires the `filehouse:share:*` permission on the bucket **and** the
method's verb (`read` for GET/HEAD, `write` for PUT).

### Redemption

```
GET | HEAD | PUT /presign/{bucket}/{key}?sig=<token>
```

The `sig` query parameter is the only credential: no `Authorization` header is
involved. The token is bound to its method, bucket and key, so a URL cannot be
redirected to another object.

| Condition | Answer |
| --- | --- |
| `sig` missing or blank | `403 presign_invalid` |
| Forged, malformed, or method/bucket/key mismatch | `403 presign_invalid` (identical response, no probing oracle) |
| Expired | `410 presign_expired` |
| A `GET` token used with `HEAD` | Allowed |
| A `PUT` request | Requires a PUT token |
| Permissions changed after minting | `403 insufficient_permissions` with `reason: permissions changed` |
| Permission lookup failed | `503 iam_unavailable` |

On redemption the service re-fetches the signed subject's effective permissions
and compares their version with the `perm_ver` embedded in the token, so revoking
a grant invalidates outstanding links immediately. See
[Permissions](/guide/permissions) for the model.

A redeemed GET/HEAD supports the same reads as the authenticated path, plus
`download=1`, which adds `Content-Disposition: attachment; filename="<basename of
key>"` for browser downloads. A redeemed PUT accepts the same
`X-Filehouse-SHA256` and `X-Filehouse-Meta-*` headers as a direct PUT and answers
`201` with the object row; the body is capped by both the token's `max_bytes` and
the object limit (`413 payload_too_large`), and quotas are enforced the same way.

```sh
# Presigned download (no Authorization header)
curl -sS "$URL" -o report.pdf

# Presigned download as an attachment
curl -sS "$URL&download=1" -o report.pdf

# Presigned upload
curl -sS -X PUT "$PUT_URL" -H 'Content-Type: application/pdf' \
  --data-binary @report.pdf
```

The URL origin is `FILEHOUSE_PUBLIC_BASE_URL` when configured; otherwise it is
derived from the request's scheme and `Host` header, which is only safe behind a
trusted proxy — set the variable in production and include the reverse proxy's
route prefix.

## Content dedup and overwrite semantics

Blob files are keyed by the SHA-256 of their bytes; uploading identical content
again shares the existing file and only increments its reference count. `ETag`
(quoted) and `X-Filehouse-SHA256` (bare) are that SHA-256 — never an MD5.

`PUT` is a replace-by-key operation and always answers `201`:

- an existing key keeps `used_objects` unchanged and adjusts `used_bytes` by
  `new size − previous size`; the previous blob's reference count is decremented
  and the new one is incremented (or reused when the bytes are identical),
- the write is committed in one transaction, so counters and object rows cannot
  drift apart.

Deleting an object removes the row and decrements the reference count immediately,
but the blob file is only unlinked later by the reaper, after the reference count
reaches zero and the `FILEHOUSE_GC_GRACE` window (default 1h) has passed. Logical
usage and quota therefore drop immediately; physical disk usage lags behind.

## Quota enforcement

Quotas are checked in the metadata transaction that commits the object, after
the bytes have been staged:

- the bucket's `quota_bytes` / `quota_objects`,
- the per-`user` quota of the object's owner,
- the per-`team` quota of the bucket's team.

A transaction that would exceed any limit is rolled back — counters and
reference counts do not change — and the request answers `413 quota_exceeded`.
Size caps answer the same `413` status with the `payload_too_large` code. `0` in
any quota dimension, or a missing quota row, means unlimited. Direct PUT,
multipart completion and presigned PUT all converge on this same path. Check your
current usage with `GET /api/v1/usage`.

## Reading objects

`GET` and `HEAD /api/v1/buckets/{bucket}/objects/{key}` return the stored bytes
with these headers:

- `Content-Type` — the stored content type,
- `ETag: "<sha256>"` and `X-Filehouse-SHA256: <sha256>`,
- `X-Filehouse-Meta-<Name>` for every stored metadata entry,
- `Last-Modified`, `Accept-Ranges`, `Content-Length` (and `Content-Range` on
  partial responses).

Reads support byte ranges and conditional requests:

| Request | Answer |
| --- | --- |
| `Range: bytes=0-1023` | `206` with `Content-Range`; `416` when unsatisfiable. |
| `If-None-Match` / `If-Modified-Since` matching the object | `304` (no body). |
| `If-Match` / `If-Unmodified-Since` not matching | `412`. |
| `If-Range` | Honored. |
| `HEAD` | Headers only, same statuses as `GET`. |

Add `?download=1` to force a browser download via
`Content-Disposition: attachment`. Missing objects answer `404 object_not_found`
(and `404 bucket_not_found` when the bucket itself is gone).

## Related pages

- [API reference: Objects](/api/reference/objects) and
  [Uploads](/api/reference/uploads) — per-route contracts and error codes.
- [Getting started](/guide/getting-started) — build, run and first requests.
- [Permissions](/guide/permissions) — who may read, write, delete and share.
- [API overview](/api/overview) — pagination, idempotency and body limits.
