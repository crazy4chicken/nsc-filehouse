---
title: Getting started
outline: 2
---

# Getting started

`nsc-filehouse` is the object storage microservice of the Nekostick fleet. Object
metadata lives in PostgreSQL, object bytes live in a local content-addressed blob
directory, and every request is authenticated and authorized through
[teamusers](https://crazy4chicken.github.io/nsc-teamusers/) IAM. The service never
issues tokens and stores no identities.

This page builds and starts a local instance, then walks through the first API
calls: obtaining a token, creating a bucket, uploading and downloading an object,
and sharing a presigned URL. For the full HTTP contract see the
[API overview](/api/overview); for production deployment see
[Deployment](/deployment).

## Prerequisites

- Go 1.26 or newer to build the service.
- PostgreSQL 16+ with an empty database. The embedded migrations are applied
  automatically at startup; the deployment role needs DDL rights on that database.
- A reachable teamusers deployment, plus service credentials for this instance:
  a client id/secret pair (recommended) or a static service token.
- A teamusers admin token for the one-time permission catalog registration. The
  token must be allowed to manage permissions in teamusers.

## Build

```sh
go build -o filehouse ./cmd/filehouse

# Include the optional NATS invalidation-event subscription:
go build -tags nats -o filehouse ./cmd/filehouse
```

For a static Linux artifact (Nekostick/compose) and release packaging, follow
[Deployment](/deployment).

## Minimal configuration

Configuration precedence is **CLI flag > `FILEHOUSE_*` environment variable >
Nekostick `HOST`/`PORT` > built-in default**. The smallest useful set:

```sh
export FILEHOUSE_DSN='postgres://filehouse:filehouse@127.0.0.1:5432/filehouse?sslmode=disable'
export FILEHOUSE_TEAMUSERS_BASE_URL='https://iam.example.com'
export FILEHOUSE_TEAMUSERS_CLIENT_ID='filehouse'
export FILEHOUSE_TEAMUSERS_CLIENT_SECRET='********'
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `FILEHOUSE_DSN` | — (required) | PostgreSQL connection string. |
| `FILEHOUSE_TEAMUSERS_BASE_URL` | — (required) | teamusers base URL; JWKS is read from `<base>/.well-known/jwks.json`. |
| `FILEHOUSE_TEAMUSERS_CLIENT_ID` / `_CLIENT_SECRET` | — (one credential is required) | Rotating service credentials used for permission lookups and catalog registration. A static `FILEHOUSE_TEAMUSERS_SERVICE_TOKEN` is also supported. |
| `FILEHOUSE_ADDR` / `FILEHOUSE_PORT` | `127.0.0.1` / `8080` | Listener; `FILEHOUSE_PORT=0` picks a free port. |
| `FILEHOUSE_BLOB_DIR` | `data` | Root of the content-addressed store (`blobs/`, `tmp/`, `uploads/`). Must be a persistent local volume. |
| `FILEHOUSE_KEY_DIR` | `data/keys` | Local secret files, including the presign HMAC key. Back it up: losing it invalidates outstanding presigned URLs. |
| `FILEHOUSE_PUBLIC_BASE_URL` | empty | Absolute origin used to build presigned links. Set it behind a reverse proxy or shared links point at the internal address. |

The full table is documented in [.env.example](https://github.com/crazy4chicken/nsc-filehouse/blob/main/.env.example)
and the [Manual](/manual).

## Register the permission catalog (one-time)

The service owns a catalog of 13 permission keys; register them in teamusers once
per deployment. Registration is an idempotent upsert and can be re-run at any time:

```sh
FILEHOUSE_TEAMUSERS_ADMIN_TOKEN='********' ./filehouse register-permissions

# or pass the token explicitly:
./filehouse register-permissions --token "$ADMIN_TOKEN"
```

The command prints every registered key. Registering the catalog does not grant
anything by itself — roles and bindings still have to be assigned to users and
teams. See [Permissions](/guide/permissions) for the key list and the
authorization model.

## Run

```sh
./filehouse run        # default subcommand; -h lists every flag
```

Two commands help before and during operation:

```sh
./filehouse status     # effective configuration with secrets masked
./filehouse doctor     # database, migrations, blob dir, key dir, IAM reachability
```

`doctor` prints one `PASS`, `FAIL` or `SKIP` line per check (`postgres`,
`migrations`, `blob-dir`, `key-dir`, `iam`) and exits non-zero when a check fails.

### Health checks

```sh
curl -fsS http://127.0.0.1:8080/healthz   # {"status":"ok"}
curl -fsS http://127.0.0.1:8080/readyz    # {"status":"ready"}
```

`healthz` is pure process liveness and never touches a dependency. `readyz` pings
PostgreSQL and verifies the blob directory is writable; when either fails it
answers `503` with `{"status":"unavailable"}` (plain JSON, not an RFC 9457 problem
document).

## First requests

The examples assume `BASE=http://127.0.0.1:8080` and a running teamusers that
issues the access tokens.

### 1. Get an access token

The service neither signs nor refreshes tokens. User login and refresh happen in
teamusers; a service identity can use client credentials:

```sh
TOKEN=$(curl -sS -X POST "$FILEHOUSE_TEAMUSERS_BASE_URL/auth/client-credentials" \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"filehouse","client_secret":"********"}' | jq -r .access_token)
```

Every `/api/v1/*` request carries `Authorization: Bearer $TOKEN`. The token only
proves identity — permissions are evaluated separately on each request, so the
caller's roles must include the matching `filehouse:*` keys (step 2 needs a
`filehouse:write:*` grant on the new bucket).

### 2. Create a bucket

```sh
curl -sS -X POST "$BASE/api/v1/buckets" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"reports"}'
```

A `201` returns the bucket row. Bucket names must match
`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$` (3–63 characters). Add `"team_id":"core"` to
create a team-owned bucket; omit it for a personal one. If the bucket already
exists the API answers `409 bucket_exists`.

### 3. Upload an object

```sh
SHA=$(sha256sum report.pdf | cut -d' ' -f1)
curl -sS -X PUT "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/pdf' \
  -H "X-Filehouse-SHA256: $SHA" \
  --data-binary @report.pdf
```

`X-Filehouse-SHA256` is optional: when present it must match the received bytes or
the request fails with `422 checksum_mismatch`. The response is `201` with the
object row; the `ETag` (`"<sha256>"`) and `X-Filehouse-SHA256` (`<sha256>`)
headers identify the content. Uploading to an existing key replaces it and still
returns `201`. See [Uploads and downloads](/guide/uploads) for multipart uploads
and metadata headers.

### 4. Download with headers and a byte range

```sh
# Read the metadata: ETag, content type, custom X-Filehouse-Meta-* headers.
curl -sSI "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN"

# Fetch the first KiB: 206 Partial Content with Content-Range.
curl -sS -r 0-1023 "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN" -o head.bin
```

Standard conditional requests are supported: `If-None-Match`/`If-Modified-Since`
answer `304`, `If-Match`/`If-Unmodified-Since` mismatches answer `412`, and an
unsatisfiable `Range` answers `416`.

### 5. Mint and redeem a presigned URL

Presigned URLs let a browser or a third party read or write a single object
without an access token:

```sh
URL=$(curl -sS -X POST "$BASE/api/v1/presign" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"bucket":"reports","key":"2026/report.pdf","method":"GET","ttl_seconds":600}' \
  | jq -r .url)
```

The response contains the signed `url` plus `method`, `bucket`, `key` and
`expires_at`. Redeem it with a plain GET — no `Authorization` header:

```sh
curl -sS "$URL" -o report.pdf
```

Minting requires the `filehouse:share:*` permission on the bucket **and** the
verb's permission (`read` for GET/HEAD, `write` for PUT). The link is bound to its
method, bucket and key, and permission changes invalidate outstanding links. See
[Uploads and downloads](/guide/uploads) for the full presign contract.

## Next steps

- [Uploads and downloads](/guide/uploads) — multipart, presigning, dedup,
  overwrite and quota semantics, Range/conditional reads.
- [Permissions](/guide/permissions) — the 13-key catalog, the scope cascade and
  failure modes.
- [API overview](/api/overview) — base URL, auth classes, pagination,
  idempotency, body limits and the generated reference.
- [Deployment](/deployment) — Nekostick compose, reverse proxy, backups and
  upgrades.
