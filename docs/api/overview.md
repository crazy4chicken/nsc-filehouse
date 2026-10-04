# API overview

## Use cases

Use this API when a workload needs to store and serve unstructured objects while identity, teams, and permissions already live in [teamusers](https://crazy4chicken.github.io/nsc-teamusers/). filehouse keeps object metadata in PostgreSQL and bytes in a local content-addressed blob directory; it never issues tokens and re-evaluates authorization against teamusers on every request. The HTTP surface is split into four planes:

- **Public system plane**: `GET /healthz` and `GET /readyz` are unauthenticated probes. `/healthz` never touches dependencies and always answers `200 {"status":"ok"}`; `/readyz` checks PostgreSQL and blob-directory writability and answers `200 {"status":"ready"}` or `503 {"status":"unavailable"}`.
- **Authenticated data plane**: every other route under `/api/v1/*` requires a teamusers-issued bearer JWT. It covers buckets, objects, multipart uploads, usage, self-service permissions, and presigned-URL minting.
- **Administrative plane**: `/api/v1/admin/*` (platform stats, subject quotas, manual garbage collection) requires `filehouse:manage:any`. Setting quota fields of a bucket through `PATCH /api/v1/buckets/{bucket}` needs it too.
- **Presign redemption plane**: `/presign/{bucket}/*` is public. The HMAC-SHA256 token in the `sig` query parameter is the only credential; no `Authorization` header is involved. Links are minted on the authenticated plane by `POST /api/v1/presign`.

The per-tag reference pages are native VitePress pages derived at build time from the canonical OpenAPI document - [System](./reference/system), [Buckets](./reference/buckets), [Objects](./reference/objects), [Uploads](./reference/uploads), [Presign](./reference/presign), [Self-service](./reference/self-service), and [Admin](./reference/admin). Do not hand-edit generated reference output.

## Base URL and Nekostick

The local base URL is `http://localhost:8080` (`FILEHOUSE_ADDR` defaults to `127.0.0.1`, `FILEHOUSE_PORT` to `8080`). The process speaks plain HTTP and does not terminate TLS; deploy TLS at the reverse-proxy boundary.

In a Nekostick deployment the host owns the external prefix and strips it before forwarding. With `route.prefix: /files` and `strip: true`, a request to `https://files.example.com/files/api/v1/buckets` reaches the process as `/api/v1/buckets`, and the probes are published at `https://files.example.com/files/healthz` and `/readyz`. Set `FILEHOUSE_PUBLIC_BASE_URL` to the externally reachable prefix - `https://files.example.com/files` in this example - because `POST /api/v1/presign` uses it to build the link's `url`; without it, minted links point at the internal lease address. Presigned links travel through the same prefix: `https://files.example.com/files/presign/{bucket}/{key}?sig=...`. See the [deployment guide](../deployment) for the compose template and proxy rules.

```sh
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```

## Authentication classes

Access tokens are bearer JWTs issued by teamusers and verified locally against teamusers' JWKS. They carry identity claims (`sub`, `kind` = `user` or `service`, an optional `team`, and `perm_ver`) but **no permissions**; every request evaluates `filehouse:<verb>:<scope>` against teamusers permission data before it touches storage.

| Caller | Credential | Typical endpoints |
| --- | --- | --- |
| Anonymous client | None | `GET /healthz`, `GET /readyz` |
| User bearer | `Authorization: Bearer <access-token>` (`kind: user`) | buckets, objects, uploads, `/api/v1/usage`, `/api/v1/me/permissions` |
| Service bearer | `Authorization: Bearer <service-access-token>` (`kind: service`) | the same `/api/v1/*` data routes |
| Admin subject | either bearer plus `filehouse:manage:any` | `/api/v1/admin/*`; quota fields of `PATCH /api/v1/buckets/{bucket}` |
| Presign link holder | none - the `sig` query token is the only credential | `GET`/`HEAD`/`PUT /presign/{bucket}/*` |

Minting a presigned URL (`POST /api/v1/presign`) requires `filehouse:share:<scope>` and, on the same bucket, the verb matching the link method: `read` for `GET`/`HEAD` and `write` for `PUT`.

Missing, malformed, expired, or unverifiable tokens answer `401` with detail `invalid_token`, and no `WWW-Authenticate` header is set. Authorization cascades broadest-first - `filehouse:<verb>:any`, then `filehouse:<verb>:team`, then `filehouse:<verb>:own` - the first matching grant wins and an explicit deny is terminal. The service fails closed: an inaccessible authorizer answers `503 iam_unavailable`, never a silent allow. Acting on another subject's multipart upload additionally requires the `:any` scope of the operation verb, and presigned links re-check the signed `perm_ver` at redemption, so a permission change invalidates outstanding URLs (`403 insufficient_permissions` with reason `permissions changed`). See the [permissions guide](../guide/permissions).

## JSON and problem+json

Successful JSON responses use `Content-Type: application/json; charset=utf-8`. Failures use RFC 9457 `application/problem+json` (with `X-Content-Type-Options: nosniff`):

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "detail": "insufficient_permissions",
  "instance": "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
  "reason": "no matching grant for filehouse:read:any, filehouse:read:team, filehouse:read:own"
}
```

`type`, `title`, and `status` are always present. `detail` carries a stable error code; `instance` is the request ID, also echoed in the `X-Request-ID` response header. Authorization denials (`403 insufficient_permissions`) add a `reason` member listing the attempted permission keys or the failure reason.

The stable `detail` codes are `invalid_request`, `invalid_token`, `invalid_bucket_name`, `invalid_key`, `bucket_not_found`, `bucket_exists`, `bucket_not_empty`, `object_not_found`, `upload_not_found`, `upload_expired`, `payload_too_large`, `checksum_mismatch`, `quota_exceeded`, `part_mismatch`, `idempotency_in_progress`, `idempotency_conflict`, `insufficient_permissions`, `presign_invalid`, `presign_expired`, `iam_unavailable`, and `service_unavailable`.

Unknown paths answer `404 invalid_request` and a known path with an unregistered method answers `405 invalid_request`. `GET /readyz` is the one exception to the problem format: a failing dependency answers `503 {"status":"unavailable"}` as plain JSON. Per-route statuses and codes are listed on the reference pages.

## Idempotency for POST requests

The five POST endpoints on the authenticated plane - `POST /api/v1/buckets`, `POST /api/v1/buckets/{bucket}/uploads`, `POST /api/v1/buckets/{bucket}/uploads/{uploadID}/complete`, `POST /api/v1/presign`, and `POST /api/v1/admin/gc` - honor the optional `Idempotency-Key` header. Other methods and all public routes ignore it, and presigned `PUT` redemption is never idempotency-wrapped.

The key is scoped to the SHA-256 digest of the raw `Authorization` header (with a client-IP fallback for header-less requests), so the same subject retrying with a different token uses a different scope. Requests are fingerprinted over the method, request URI, and body prefix. The middleware reads at most 64 KiB of the body: a request body **larger than 64 KiB executes normally but is never tracked or replayed**. A key that is empty or longer than 1024 bytes disables idempotency for that request.

- Retrying with the same scope, key, and fingerprint replays the original status, body, and `Content-Type`, plus `Idempotency-Replayed: true`. Other headers from the original response (`ETag`, `X-Filehouse-SHA256`, `X-Filehouse-Meta-*`) are not replayed.
- The same key while the original request is still executing answers `409 idempotency_in_progress`.
- The same key with a different fingerprint answers `422 idempotency_conflict`.
- Completed responses are retained for the idempotency TTL (default `24h`, `FILEHOUSE_IDEMPOTENCY_TTL`). Only statuses in `200`-`428` with a body of at most 64 KiB are kept; everything else marks the key dead so it can be reused.

## Cursor pagination

The three collection endpoints - `GET /api/v1/buckets`, `GET /api/v1/buckets/{bucket}/objects`, and `GET /api/v1/admin/quotas` - accept `limit` and an opaque `cursor`, and answer `{"items": [...], "next_cursor": "..."}`:

```sh
curl -sS -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/v1/buckets?limit=25&cursor='
```

- `limit`: absent, empty, or `0` selects the default 100; values above 1000 are clamped to 1000; negative or non-numeric values answer `400 invalid_request`.
- `cursor` and `next_cursor` are opaque URL-safe base64 tokens. Pass `next_cursor` back verbatim as `cursor`; an empty `next_cursor` means the page is the last one.
- Cursors are scope-bound: an object cursor encodes the bucket and `prefix`, a quota cursor the `kind` filter, and a bucket cursor the caller's readable scope. Reusing a cursor after changing the filter (or the caller's grants) answers `400 invalid_request`.
- Ordering is `name` ascending for buckets, `key` ascending for objects, and `(subject_kind, subject_id)` for quotas.

## Request body and size limits

| Limit | Default | Where it applies |
| --- | --- | --- |
| JSON request body | 1 MiB | create/patch bucket, initiate/complete upload, presign mint, admin quota upsert; exceeding answers `413 payload_too_large` |
| Object size | 5 GiB (`FILEHOUSE_OBJECT_MAX_BYTES`) | direct object PUT, multipart complete, presigned PUT |
| Part size | 256 MiB (`FILEHOUSE_PART_MAX_BYTES`) | `PUT /api/v1/buckets/{bucket}/uploads/{uploadID}/parts/{partNo}` |
| Multipart upload lifetime | 24h (`FILEHOUSE_UPLOAD_TTL`) | expired uploads answer `410 upload_expired` |
| Presign TTL | 15m default, 24h maximum (`FILEHOUSE_PRESIGN_DEFAULT_TTL`, `FILEHOUSE_PRESIGN_MAX_TTL`) | `ttl_seconds` on `POST /api/v1/presign`; above the maximum answers `400 invalid_request` |

Writes converge on one commit path: an object PUT answers `201` even when it overwrites an existing key, identical SHA-256 content shares a single blob file, and a quota rejection (bucket, owner, or team quota; `0` means unlimited) answers `413 quota_exceeded`. The service has no request-rate limiting; apply it at the ingress proxy if needed. See the [uploads guide](../guide/uploads) for the full direct-upload, multipart, and presign flows.

## Contract source

Go emits the single canonical OpenAPI 3.1 document from the handler metadata in `internal/httpapi/doc.go`; `go run ./cmd/genspec` writes it to `docs/public/openapi.yaml`. The YAML is generated at build time - as the `predocs:dev` and `predocs:build` pre-steps of `pnpm docs:dev` and `pnpm docs:build` - and is not committed. VitePress parses it during the build to derive the native pages under `/api/reference/`, one page per tag, so endpoint details stay in Go rather than in hand-edited pages. Download the machine-readable contract from [`openapi.yaml`](../openapi.yaml).

New here? Start with [Getting started](../guide/getting-started); the [manual](../manual) holds the full configuration reference.
