---
title: Permissions
outline: 2
---

# Permissions

`nsc-filehouse` holds no identities of its own. Every `/api/v1/*` request is
authenticated against [teamusers](https://crazy4chicken.github.io/nsc-teamusers/)
and authorized locally with the permission data teamusers publishes. This page
explains what a token proves, the 13-key catalog the service owns, how a request
is decided, and how revocation and presigned URLs interact with the permission
cache.

## Tokens prove identity only

Requests carry `Authorization: Bearer <access-token>`. The token is verified
against the teamusers JWKS document at `<FILEHOUSE_TEAMUSERS_BASE_URL>/.well-known/jwks.json`:

- the signature is checked with the Ed25519 key referenced by the token's `kid`,
- `iss` must match `FILEHOUSE_TEAMUSERS_ISSUER`, `aud` must match
  `FILEHOUSE_TEAMUSERS_AUDIENCE` (empty variables select the teamusers defaults),
- `exp` must be in the future.

A missing, malformed, unverifiable or expired token is rejected with `401
invalid_token` (RFC 9457 problem document). **Access tokens never carry
permissions** — they only establish the subject, its kind (`user` or `service`)
and its optional team. Permissions are looked up separately for every decision
and must never be inferred from token contents.

## The permission catalog

The service owns 13 permission keys. The list below is the exact catalog
registered in teamusers:

| Permission key | Description |
| --- | --- |
| `filehouse:read:own` | Read objects and list buckets the subject owns |
| `filehouse:read:team` | Read objects and list buckets owned by the subject's team |
| `filehouse:read:any` | Read any object or bucket on the platform |
| `filehouse:write:own` | Upload objects, create personal buckets, and manage multipart uploads in buckets the subject owns |
| `filehouse:write:team` | Upload objects and manage multipart uploads in buckets owned by the subject's team |
| `filehouse:write:any` | Upload objects and manage multipart uploads in any bucket |
| `filehouse:delete:own` | Delete objects and empty buckets the subject owns |
| `filehouse:delete:team` | Delete objects and empty buckets owned by the subject's team |
| `filehouse:delete:any` | Delete any object or empty bucket on the platform |
| `filehouse:share:own` | Mint presigned URLs for objects in buckets the subject owns |
| `filehouse:share:team` | Mint presigned URLs for objects in buckets owned by the subject's team |
| `filehouse:share:any` | Mint presigned URLs for any object on the platform |
| `filehouse:manage:any` | Administer quotas, platform statistics, and garbage collection |

Registration is a one-time, idempotent upsert (`POST
{baseURL}/permissions/`, registered by `filehouse`) and can be re-run at any
time:

```sh
FILEHOUSE_TEAMUSERS_ADMIN_TOKEN='********' ./filehouse register-permissions

# or pass the token explicitly:
./filehouse register-permissions --token "$ADMIN_TOKEN"
```

Registering the catalog only defines the keys; it grants nothing. Roles and
bindings still have to be assigned to users and teams in teamusers, as shown in
[Deployment](/deployment).

## The scope cascade

Each request is decided against the concrete resource — for buckets and objects
that means the bucket's owner and team. The service asks for permission keys
**broadest scope first**:

1. `filehouse:{verb}:any`,
2. `filehouse:{verb}:team`, only when the resource belongs to a team,
3. `filehouse:{verb}:own`, only when the resource owner is the calling subject.

The first allow wins. An explicit deny grant (a `!`-prefixed key) is terminal:
the decision stops at that key and cannot be rescued by a narrower scope. An
exhausted cascade denies. Wildcards are supported in grants: a `*` segment
matches exactly one segment, so `filehouse:read:*` covers own, team and any.

The verb depends on the operation, not only on the HTTP method:

| Operation | Permission keys attempted |
| --- | --- |
| Read a bucket/object, list buckets or objects (`GET`/`HEAD`) | `read` |
| Create a bucket; upload an object or part; complete or abort an upload; patch a bucket | `write` |
| Delete an object or an empty bucket | `delete` |
| Mint a presigned URL | `share` **and** `read` (GET/HEAD) or `write` (PUT) |
| Admin statistics, quota management, garbage collection | `manage:any` only |

A few operations add a second requirement:

- `PATCH /api/v1/buckets/{bucket}` needs `write` on the bucket, and additionally
  `filehouse:manage:any` when the body changes `quota_bytes` or `quota_objects`.
- Acting on **another subject's** multipart upload (inspect, write parts,
  complete, abort) requires `write`/`read` on the bucket *and* the `:any` scope
  of that verb.
- Listing buckets silently drops rows the caller may not read; when no readable
  grant exists at all, the request is denied.

## Denials and failure modes

A denied decision answers `403` with the RFC 9457 problem document
(`title: Forbidden`, `detail: insufficient_permissions`) and an extra `reason`
member that lists the attempted keys or the failing check, for example:

- `no matching grant for filehouse:read:any, filehouse:read:team, filehouse:read:own`
- `denied by filehouse:write:team`
- `permissions changed`

Authorization is **fail-closed**: if a decision cannot be made — the authorizer
is not ready, the permission lookup fails, or the presigned subject's permissions
cannot be fetched — the request answers `503 iam_unavailable` and is never
allowed.

The 401/403/503 split is deliberate:

| Response | Meaning |
| --- | --- |
| `401 invalid_token` | The bearer token is missing or failed verification (signature, issuer, audience, expiry). |
| `403 insufficient_permissions` | The token is valid, but no grant allowed the operation; `reason` says why. |
| `503 iam_unavailable` | The decision could not be evaluated; retry after the IAM dependency recovers. |

## Caching and permission changes

Decisions are served from a local effective-permission cache with a **two-minute
TTL**, filled with the service's teamusers credentials (client credentials or a
static service token). A cache miss or expiry triggers a fetch from teamusers;
concurrent lookups of the same subject are single-flight. A cached entry is only
reused while its permission version matches the token's, so a token minted before
a change refetches the authoritative set.

When the service is built with `-tags nats` and `FILEHOUSE_TEAMUSERS_NATS_URL` is
set, permission invalidation events drop affected cache entries immediately.
Without that subscription, a permission change takes effect within the cache TTL
(~2 minutes).

Permission changes also invalidate outstanding presigned URLs: the minted token
embeds the subject's `perm_ver`, and redemption re-fetches the effective
permissions and compares the version. A mismatch denies the redemption with `403
insufficient_permissions` and `reason: permissions changed`; a failed fetch is
`503 iam_unavailable`. [Uploads and downloads](/guide/uploads) documents the
redemption contract.

## Inspecting effective permissions

`GET /api/v1/me/permissions` returns the caller's effective grants (the subject
is always taken from the token):

```json
{
  "subject": {"id": "01J8ZQ4F7G9K2M3N4P5Q6R7S8T", "kind": "user"},
  "permissions": ["filehouse:read:own", "filehouse:share:own", "filehouse:write:own"]
}
```

The list is sorted; deny grants keep their `!` prefix and wildcards are
preserved. `GET /api/v1/usage` shows the caller's storage usage and quotas.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `401 invalid_token` | Expired token, `iss`/`aud` mismatch, or the JWKS endpoint is unreachable | Align `FILEHOUSE_TEAMUSERS_AUDIENCE`/`_ISSUER` with teamusers; `doctor` checks JWKS reachability. |
| `403 insufficient_permissions` with a `reason` listing keys | The subject holds no matching grant | Bind the listed `filehouse:*` key (or a broader one) to the subject's role in teamusers. |
| Permission changes seem ignored | The local cache has not expired yet | Wait out the ~2-minute TTL, or enable NATS invalidation events. |
| `503 iam_unavailable` | The authorizer is not ready, or teamusers is unreachable / the service credentials are invalid | Check `FILEHOUSE_TEAMUSERS_BASE_URL` and the client id/secret; see the `iam` line of `doctor`. |
| Presigned URL fails with `permissions changed` | The signed subject's permissions changed after minting | Mint a new URL; the old link is permanently invalidated. |

## Related pages

- [Getting started](/guide/getting-started) — including the one-time catalog
  registration.
- [Uploads and downloads](/guide/uploads) — presigned URLs and multipart
  ownership rules.
- [API reference: Self-service](/api/reference/self-service) and
  [Admin](/api/reference/admin) — the endpoints behind `read` on your own data
  and `manage:any`.
- [Deployment](/deployment) — creating the service account, roles and bindings in
  teamusers.
