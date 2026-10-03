# AGENTS.md — working in nsc-filewarehouse

Object storage microservice for the Nekostick fleet: PostgreSQL metadata plus a
content-addressed local blob directory. Authentication and authorization are
delegated to the teamusers IAM service through its official Go SDK
(`github.com/crazy4chicken/nsc-teamusers/sdk/go`, imported as `iam`).

## Repository layout

```text
cmd/filewarehouse/   run/status/doctor/register-permissions, flags, signals
internal/config/     env+flag loading, validation, Redacted()
internal/id/         ULID generation (crypto/rand, no dependencies)
internal/httpx/      problem+json, request id, cursor, idempotency, client IP
internal/store/      pgx pool, goose runner, all SQL
internal/blob/       content-addressed blob store + multipart staging
internal/iamauth/    SDK wiring: verifier, permission cache, cascade, catalog
internal/presign/    HMAC-SHA256 presigned URL sign/verify, key management
internal/gc/         reaper: unreferenced and orphan blobs, expired uploads, idempotency rows
internal/httpapi/    chi router: server, middleware, runtime/admin/presign handlers
internal/iamfixture/ fake teamusers server for tests (JWKS, JWT, checks)
migrations/          0001_init.sql + embedded goose runner
test/                integration suite gated by FILEWAREHOUSE_TEST_PG
```

## Commands

```sh
go build ./cmd/filewarehouse                 # build
go run ./cmd/filewarehouse run               # serve (default subcommand)
go run ./cmd/filewarehouse status            # print redacted configuration
go run ./cmd/filewarehouse doctor            # check DB, migrations, dirs, IAM
go run ./cmd/filewarehouse register-permissions   # upsert the permission catalog
go build -tags nats ./cmd/filewarehouse      # enable NATS invalidation events
gofmt -l cmd internal test                   # formatting check
```

Configuration precedence is CLI flag > `FILEWAREHOUSE_*` > Nekostick `HOST`/`PORT`
> built-in default; every variable is documented in `.env.example` and `README.md`.
Nothing is required beyond a DSN, the teamusers base URL and either a service
token or a client id/secret pair.

## Architecture invariants

- **Tokens prove identity only.** An access token is verified against the
  teamusers JWKS; its claims say who the caller is. Permissions are never
  embedded in tokens and must never be inferred from token contents.
- **Authorization is always an SDK decision.** Handlers call
  `Authorizer.Decide`/`DecideSubject` and act on the result; deny wins over
  allow at every level (explicit `!` grants, narrower scope preferences, and
  fail-closed errors). A failed IAM call is a 503, never an allow.
- **The scope cascade is broadest-first.** `any` → `team` (only when
  `TeamID != ""`) → `own` (only when `OwnerID == subject`); the first allow
  wins, an explicit deny is terminal, an exhausted cascade denies.
- **Counter and refcount integrity is transactional.** Bucket counters
  (`used_bytes`, `used_objects`), object rows and blob `refcount` move in one
  transaction under `SELECT ... FOR UPDATE`; quota rejection happens before
  commit. Never update these counters outside the store.
- **Blobs are content-addressed.** The key is the SHA-256 of the stored bytes;
  blob files are only removed by the reaper after `refcount = 0` and after the
  GC grace period; orphan files written but never committed to an object (e.g.
  a quota-rejected upload or a crash) are reclaimed the same way, and the grace
  window is what protects in-flight uploads from the sweep. `ETag` and
  `X-Filewarehouse-SHA256` are the quoted lowercase SHA-256, never an MD5.
- **Blob removal is not atomic with concurrent writers of identical content.**
  Removing a blob (guarded row delete, then file unlink) can interleave with a
  concurrent upload of the same content — specifically a delete racing a failed
  commit plus a concurrent identical upload — and leave an object row whose
  blob file was removed. The window is milliseconds, the supported topology is
  one replica per blob directory, and the recovery is re-uploading the object.
- **Audit is not implemented.** Do not claim audit logging, tamper-evident
  trails or retention anywhere in code, docs, or API responses.
- **Secrets stay out of logs and `status`.** Tokens, client secrets and the
  presign key are never logged; configuration output is redacted.

## Adding a route

1. Register it inside the authenticated group in `internal/httpapi` and pick
   the permission the handler enforces.
2. Resolve the bucket first, build the resource context
   (`OwnerID`, `TeamID`, `Attrs{"bucket","key","size","content_type","uploader"}`)
   and call `Authorizer.Decide` with the matching verb
   (`read|write|delete|share|manage`). Cross-subject admin operations call
   `Decide` with an empty `iam.Resource`, which restricts the cascade to the
   `:any` scope.
3. Map errors to the stable codes in the contract (`insufficient_permissions`
   403, `_not_found` 404, `quota_exceeded` 413, ...); unknown failures stay
   fail-closed with `service_unavailable`/`iam_unavailable` (503).
4. Update the route table in `README.md` and the test suite.

## Configuration surface

Full table in `README.md` (section "Configuration") and commented defaults in
`.env.example`. The two knobs that change behavior most: presign lifetimes
(`FILEWAREHOUSE_PRESIGN_DEFAULT_TTL`/`MAX_TTL`) and the GC grace period
(`FILEWAREHOUSE_GC_GRACE`).

## Tests

```sh
# Unit tests only (integration tests skip without the gate).
go test ./...

# Full integration suite against a disposable PostgreSQL database.
FILEWAREHOUSE_TEST_PG='postgres://postgres:postgres@127.0.0.1:5432/filewarehouse_test?sslmode=disable' \
  go test ./test/... -count=1
```

- `FILEWAREHOUSE_TEST_PG` gates `test/`; leave it unset for `go test ./...` on
  machines without PostgreSQL. The suite truncates every table before each test
  and uses temp directories, so it never touches production data.
- `internal/iamfixture` is the fake teamusers instance used by the suite: real
  Ed25519 JWTs and JWKS, permission cache responses, deny/condition checks,
  client-credentials exchange and permission registration. Tests should keep
  asserting observable HTTP behavior instead of internal wiring.
- Never run `go mod tidy`; dependencies are intentionally limited to chi, pgx,
  goose and the teamusers SDK.
