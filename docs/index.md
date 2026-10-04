---
layout: home

hero:
  name: Filehouse
  text: Object storage for the Nekostick fleet
  tagline: Buckets, objects, multipart uploads and presigned URLs on PostgreSQL metadata and content-addressed blob storage, authorized by teamusers.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/overview

features:
  - title: Buckets and objects
    details: Buckets belong to an owner or a team and address objects by bucket/key. Overwrite writes, prefix listing with opaque cursors, and Range downloads are supported out of the box.
  - title: Multipart uploads
    details: Initiate, upload parts, complete or abort. Parts are staged first, then assembled in order and go through the same quota and deduplication path as a direct upload.
  - title: Presigned URLs
    details: Mint HMAC-SHA256 links for GET, HEAD or PUT. Browsers and third parties redeem them without an access token, bounded by the configured TTL and rechecked permissions.
  - title: Content-addressed deduplication
    details: Blobs are keyed by the SHA-256 of their bytes, so identical content is stored once. ETag and X-Filehouse-SHA256 are the quoted lowercase SHA-256, never an MD5.
  - title: Quotas and usage
    details: Per-bucket and per-subject byte and object quotas are enforced atomically inside the write transaction; GET /api/v1/usage reports the caller's own consumption.
  - title: teamusers IAM authorization
    details: Access tokens are verified against the teamusers JWKS and carry no permissions. Every request gets a fail-closed any/team/own scope decision, and POST retries can replay safely with Idempotency-Key.
---
