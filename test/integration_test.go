package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/gc"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpapi"
	"github.com/crazy4chicken/nsc-filehouse/internal/iamauth"
	"github.com/crazy4chicken/nsc-filehouse/internal/iamfixture"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// harness wires one isolated test: a truncated database, a fresh iamfixture
// teamusers server, a fresh authorizer (empty permission cache) and an HTTP
// server backed by the shared store, blob directory and presign key.
type harness struct {
	t          *testing.T
	server     *httptest.Server
	fixture    *iamfixture.Server
	authorizer *iamauth.Authorizer
	reaper     *gc.Reaper
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	s := requireSuite(t)
	truncateTables(t, s)

	fixture, err := iamfixture.New()
	if err != nil {
		t.Fatalf("start IAM fixture: %v", err)
	}
	authorizer, err := iamauth.NewAuthorizer(iamauth.Options{
		BaseURL:      fixture.URL(),
		ClientID:     iamfixture.DefaultClientID,
		ClientSecret: iamfixture.DefaultClientSecret,
		Timeout:      5 * time.Second,
		Logger:       s.logger,
	})
	if err != nil {
		fixture.Close()
		t.Fatalf("build authorizer: %v", err)
	}
	reaper := gc.New(s.store, s.blobs, s.logger, gc.Config{Interval: time.Hour})
	server := httpapi.NewServer(httpapi.Options{
		Config:     s.cfg,
		Store:      s.store,
		Blobs:      s.blobs,
		Authorizer: authorizer,
		Signer:     s.signer,
		Reaper:     reaper,
		Logger:     s.logger,
		Version:    "integration-test",
	})
	httpServer := httptest.NewServer(server.Handler())

	h := &harness{t: t, server: httpServer, fixture: fixture, authorizer: authorizer, reaper: reaper}
	t.Cleanup(func() {
		httpServer.Close()
		authorizer.Close()
		fixture.Close()
	})
	return h
}

// freshInstance starts another HTTP server that shares the store, blob store
// and signer but uses a new authorizer with an empty permission cache. It
// models a second replica (or a cache invalidated between mint and redemption).
func (h *harness) freshInstance() *httptest.Server {
	h.t.Helper()
	s := requireSuite(h.t)
	authorizer, err := iamauth.NewAuthorizer(iamauth.Options{
		BaseURL:      h.fixture.URL(),
		ClientID:     iamfixture.DefaultClientID,
		ClientSecret: iamfixture.DefaultClientSecret,
		Timeout:      5 * time.Second,
		Logger:       s.logger,
	})
	if err != nil {
		h.t.Fatalf("build second authorizer: %v", err)
	}
	server := httpapi.NewServer(httpapi.Options{
		Config:     s.cfg,
		Store:      s.store,
		Blobs:      s.blobs,
		Authorizer: authorizer,
		Signer:     s.signer,
		Reaper:     gc.New(s.store, s.blobs, s.logger, gc.Config{Interval: time.Hour}),
		Logger:     s.logger,
		Version:    "integration-test",
	})
	httpServer := httptest.NewServer(server.Handler())
	h.t.Cleanup(func() {
		httpServer.Close()
		authorizer.Close()
	})
	return httpServer
}

// authorize installs grants at permission version 1 and returns a token bound
// to that version.
func (h *harness) authorize(subject string, grants ...iamfixture.Grant) string {
	h.fixture.SetGrants(subject, 1, grants...)
	return h.fixture.Issue(iamfixture.Claims{Subject: subject, Kind: "user", PermVer: 1})
}

// seedBucket creates a bucket directly in the store; using HTTP for the object
// tests keeps bucket-creation semantics out of their assertions.
func (h *harness) seedBucket(name, ownerID, teamID string) store.Bucket {
	h.t.Helper()
	bucket, err := testSuite.store.CreateBucket(context.Background(), store.Bucket{
		Name:      name,
		OwnerID:   ownerID,
		OwnerKind: "user",
		TeamID:    teamID,
	})
	if err != nil {
		h.t.Fatalf("seed bucket %q: %v", name, err)
	}
	return bucket
}

func truncateTables(t *testing.T, s *suite) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const statement = `TRUNCATE TABLE upload_parts, uploads, objects, buckets, blobs, quotas, idempotency RESTART IDENTITY CASCADE`
	if _, err := s.pool.Exec(ctx, statement); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
}

// result is one captured HTTP response.
type result struct {
	Status int
	Header http.Header
	Body   []byte
}

func (h *harness) doAgainst(t *testing.T, base, method, path, token string, body []byte, headers map[string]string) result {
	t.Helper()
	request, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s %s: build request: %v", method, path, err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := h.server.Client().Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("%s %s: read response: %v", method, path, err)
	}
	return result{Status: response.StatusCode, Header: response.Header.Clone(), Body: payload}
}

func (h *harness) mustDo(t *testing.T, method, path, token string, body []byte, headers map[string]string) result {
	t.Helper()
	return h.doAgainst(t, h.server.URL, method, path, token, body, headers)
}

func (h *harness) sendJSON(t *testing.T, method, path, token string, payload any, headers map[string]string) result {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	merged := map[string]string{"Content-Type": "application/json"}
	for name, value := range headers {
		merged[name] = value
	}
	return h.mustDo(t, method, path, token, body, merged)
}

func requireStatus(t *testing.T, got result, want int) {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status = %d, want %d (body %s)", got.Status, want, truncateBody(got.Body))
	}
}

// problemDocument mirrors the RFC 9457 body written by httpx.
type problemDocument struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
	Reason   string `json:"reason"`
}

// requireProblem asserts the status, the stable detail code and the problem
// media type, then returns the decoded document.
func requireProblem(t *testing.T, got result, status int, detail string) problemDocument {
	t.Helper()
	requireStatus(t, got, status)
	if contentType := got.Header.Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json (body %s)", contentType, truncateBody(got.Body))
	}
	var problem problemDocument
	if err := json.Unmarshal(got.Body, &problem); err != nil {
		t.Fatalf("decode problem document: %v (body %s)", err, truncateBody(got.Body))
	}
	if problem.Status != status {
		t.Fatalf("problem status = %d, want %d", problem.Status, status)
	}
	if problem.Detail != detail {
		t.Fatalf("problem detail = %q, want %q (body %s)", problem.Detail, detail, truncateBody(got.Body))
	}
	return problem
}

func decodeJSON[T any](t *testing.T, got result) T {
	t.Helper()
	var decoded T
	if err := json.Unmarshal(got.Body, &decoded); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, truncateBody(got.Body))
	}
	return decoded
}

func truncateBody(body []byte) string {
	const limit = 512
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "..."
}

// Response shapes, mirroring the JSON the handlers emit.
type bucketResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OwnerID     string `json:"owner_id"`
	TeamID      string `json:"team_id"`
	QuotaBytes  int64  `json:"quota_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	UsedObjects int64  `json:"used_objects"`
}

type bucketPage struct {
	Items      []bucketResponse `json:"items"`
	NextCursor string           `json:"next_cursor"`
}

type objectResponse struct {
	Key         string            `json:"key"`
	BlobHash    string            `json:"blob_hash"`
	Size        int64             `json:"size"`
	ETag        string            `json:"etag"`
	ContentType string            `json:"content_type"`
	Metadata    map[string]string `json:"metadata"`
}

type objectPage struct {
	Items      []objectResponse `json:"items"`
	NextCursor string           `json:"next_cursor"`
}

type initiateResponse struct {
	UploadID  string    `json:"upload_id"`
	ExpiresAt time.Time `json:"expires_at"`
	PartCount int       `json:"part_count"`
}

type partResponse struct {
	UploadID string `json:"upload_id"`
	PartNo   int    `json:"part_no"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type uploadDetail struct {
	UploadID string         `json:"upload_id"`
	Key      string         `json:"key"`
	Parts    []partResponse `json:"parts"`
}

type presignResponse struct {
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
}

type quotaResponse struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	MaxBytes    int64  `json:"max_bytes"`
	MaxObjects  int64  `json:"max_objects"`
}

type quotaPage struct {
	Items      []quotaResponse `json:"items"`
	NextCursor string          `json:"next_cursor"`
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func quotedETag(data []byte) string {
	return `"` + sha256Hex(data) + `"`
}

func (h *harness) blobRefcount(hash string) int64 {
	h.t.Helper()
	var refcount int64
	if err := testSuite.pool.QueryRow(context.Background(), `SELECT refcount FROM blobs WHERE hash = $1`, hash).Scan(&refcount); err != nil {
		h.t.Fatalf("read blob refcount: %v", err)
	}
	return refcount
}

func (h *harness) blobRowCount() int {
	h.t.Helper()
	var count int
	if err := testSuite.pool.QueryRow(context.Background(), `SELECT count(*) FROM blobs`).Scan(&count); err != nil {
		h.t.Fatalf("count blob rows: %v", err)
	}
	return count
}

// blobFileCount counts the content-addressed files physically present under the
// blob directory, including files without a blobs row.
func (h *harness) blobFileCount() int {
	h.t.Helper()
	count := 0
	err := testSuite.blobs.ListHashes(context.Background(), 0, func(string) error {
		count++
		return nil
	})
	if err != nil {
		h.t.Fatalf("list blob files: %v", err)
	}
	return count
}

// writeBlobFile plants a file directly in the content-addressed layout
// (<root>/blobs/<aa>/<bb>/<hash>), mirroring the documented blob store layout
// so a test can page the reaper's directory walk.
func (h *harness) writeBlobFile(hash string, content []byte) {
	h.t.Helper()
	path := filepath.Join(testSuite.rootDir, "blobs", hash[:2], hash[2:4], hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatalf("create blob directory: %v", err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		h.t.Fatalf("write blob file: %v", err)
	}
}

func (h *harness) bucketRow(name string) store.Bucket {
	h.t.Helper()
	bucket, err := testSuite.store.GetBucketByName(context.Background(), name)
	if err != nil {
		h.t.Fatalf("load bucket %q: %v", name, err)
	}
	return bucket
}

// objectPath builds an authenticated object path.
func objectPath(bucket, key string) string {
	return "/api/v1/buckets/" + bucket + "/objects/" + key
}

// requestPath reduces an absolute presigned URL to the request URI served by
// the harness.
func requestPath(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse presigned url %q: %v", raw, err)
	}
	return parsed.RequestURI()
}

// tamperSignature flips the first character of the sig parameter. The first
// base64url character always changes the leading signature bits, whereas the
// last one of a 43-character HMAC encoding carries only four significant bits:
// flipping it can yield an equivalent encoding that still verifies.
func tamperSignature(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse presigned url %q: %v", raw, err)
	}
	query := parsed.Query()
	signature := query.Get("sig")
	if signature == "" {
		t.Fatalf("presigned url %q carries no sig", raw)
	}
	replacement := byte('A')
	if signature[0] == 'A' {
		replacement = 'B'
	}
	query.Set("sig", string(replacement)+signature[1:])
	parsed.RawQuery = query.Encode()
	return parsed.RequestURI()
}

// TestUnauthenticatedRequestsRejected covers (1): a missing bearer token and an
// expired token are answered 401 with the matching classified detail.
func TestUnauthenticatedRequestsRejected(t *testing.T) {
	h := newHarness(t)

	problem := requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/buckets", "", nil, nil),
		http.StatusUnauthorized, "invalid_token_missing")
	if problem.Title != "Unauthorized" {
		t.Fatalf("title = %q, want Unauthorized", problem.Title)
	}
	if problem.Instance == "" {
		t.Fatal("problem document carries no request id")
	}

	h.fixture.ExpireTokens()
	expired := h.fixture.Issue(iamfixture.Claims{Subject: "alice", Kind: "user", PermVer: 1})
	h.fixture.ResetTokenExpiration()
	requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/buckets", expired, nil, nil),
		http.StatusUnauthorized, "invalid_token_expired")
}

// TestBucketOwnerAndTeamAssignment covers the assignment contract: a plain
// writer may attach its own bucket to a team at creation and may re-send the
// team it already has, but changing the owner, the owner kind or the team needs
// the platform-wide filehouse:manage:any grant, and so does creating a bucket
// for another owner.
func TestBucketOwnerAndTeamAssignment(t *testing.T) {
	h := newHarness(t)
	writer := h.authorize("alice", iamfixture.Grant{Key: "filehouse:write:own"})
	manager := h.authorize("amy",
		iamfixture.Grant{Key: "filehouse:write:own"},
		iamfixture.Grant{Key: "filehouse:manage:any"},
	)

	// A team is attachable at creation: the write decision runs against the
	// caller's own prospective bucket.
	created := h.mustDo(t, http.MethodPost, "/api/v1/buckets", writer,
		[]byte(`{"name":"assign-team","team_id":"core"}`), nil)
	requireStatus(t, created, http.StatusCreated)
	if bucket := decodeJSON[store.Bucket](t, created); bucket.OwnerID != "alice" || bucket.TeamID != "core" {
		t.Fatalf("created bucket = %+v, want owner alice in team core", bucket)
	}

	// Re-sending the team the bucket already has changes nothing.
	requireStatus(t, h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-team", writer,
		[]byte(`{"team_id":"core"}`), nil), http.StatusOK)

	// Moving the bucket to another team or another owner is a scope change.
	requireProblem(t, h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-team", writer,
		[]byte(`{"team_id":"other"}`), nil), http.StatusForbidden, "insufficient_permissions")
	requireProblem(t, h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-team", writer,
		[]byte(`{"owner":"bob"}`), nil), http.StatusForbidden, "insufficient_permissions")
	requireProblem(t, h.mustDo(t, http.MethodPost, "/api/v1/buckets", writer,
		[]byte(`{"name":"assign-foreign","owner":"bob"}`), nil), http.StatusForbidden, "insufficient_permissions")

	// The manager holds write:own plus the platform-wide manage grant.
	requireStatus(t, h.mustDo(t, http.MethodPost, "/api/v1/buckets", manager,
		[]byte(`{"name":"assign-managed"}`), nil), http.StatusCreated)

	team := h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-managed", manager,
		[]byte(`{"team_id":"core"}`), nil)
	requireStatus(t, team, http.StatusOK)
	if bucket := decodeJSON[store.Bucket](t, team); bucket.TeamID != "core" {
		t.Fatalf("team_id = %q, want core", bucket.TeamID)
	}

	reassigned := h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-managed", manager,
		[]byte(`{"owner":"bob","owner_kind":"service","team_id":""}`), nil)
	requireStatus(t, reassigned, http.StatusOK)
	if bucket := decodeJSON[store.Bucket](t, reassigned); bucket.OwnerID != "bob" || bucket.OwnerKind != "service" || bucket.TeamID != "" {
		t.Fatalf("reassigned bucket = %+v, want owner bob (service) without a team", bucket)
	}

	// The reassignment moved the bucket out of the manager's own scope.
	requireProblem(t, h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-managed", manager,
		[]byte(`{"description":"out of scope"}`), nil), http.StatusForbidden, "insufficient_permissions")

	// Invalid assignment payloads are rejected before any decision.
	requireProblem(t, h.mustDo(t, http.MethodPatch, "/api/v1/buckets/assign-managed", manager,
		[]byte(`{"owner":"  "}`), nil), http.StatusBadRequest, "invalid_request")
	requireProblem(t, h.mustDo(t, http.MethodPost, "/api/v1/buckets", manager,
		[]byte(`{"name":"assign-bad-kind","owner_kind":"robot"}`), nil), http.StatusBadRequest, "invalid_request")
}

// TestUnrelatedPermissionForbidden covers (2): a subject holding only an
// unrelated grant cannot read a foreign bucket.
func TestUnrelatedPermissionForbidden(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("read-target", "alice", "")

	token := h.authorize("bob", iamfixture.Grant{Key: "filehouse:write:own"})
	problem := requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/buckets/read-target", token, nil, nil),
		http.StatusForbidden, "insufficient_permissions")
	if problem.Reason == "" {
		t.Fatal("403 problem document carries no cascade reason")
	}
}

// TestScopeCascade covers (3): an any-scope read grant opens a team bucket, an
// explicit !read:any deny blocks an own-scope allow, and team scope grants
// access to the team's bucket.
func TestScopeCascade(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("team-shared", "team-owner", "core")

	carol := h.authorize("carol", iamfixture.Grant{Key: "filehouse:read:any"})
	opened := h.mustDo(t, http.MethodGet, "/api/v1/buckets/team-shared", carol, nil, nil)
	requireStatus(t, opened, http.StatusOK)
	if bucket := decodeJSON[bucketResponse](t, opened); bucket.Name != "team-shared" {
		t.Fatalf("bucket name = %q, want team-shared", bucket.Name)
	}

	h.seedBucket("dave-personal", "dave", "")
	dave := h.authorize("dave",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "!filehouse:read:any"})
	requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/buckets/dave-personal", dave, nil, nil),
		http.StatusForbidden, "insufficient_permissions")

	// Control: the same own-scope allow without the deny succeeds, proving the
	// explicit deny is what blocked Dave.
	h.seedBucket("erin-personal", "erin", "")
	erin := h.authorize("erin", iamfixture.Grant{Key: "filehouse:read:own"})
	control := h.mustDo(t, http.MethodGet, "/api/v1/buckets/erin-personal", erin, nil, nil)
	requireStatus(t, control, http.StatusOK)

	// Team scope: the team claim plus read:team opens the team's bucket.
	h.fixture.SetGrants("frank", 1, iamfixture.Grant{Key: "filehouse:read:team"})
	frank := h.fixture.Issue(iamfixture.Claims{Subject: "frank", Kind: "user", Team: "core", PermVer: 1})
	teamScoped := h.mustDo(t, http.MethodGet, "/api/v1/buckets/team-shared", frank, nil, nil)
	requireStatus(t, teamScoped, http.StatusOK)
}

// TestObjectRoundTripRangeAndETag covers (4): PUT/GET/HEAD byte equality, the
// sha256 ETag, Range responses and the client-supplied checksum check.
func TestObjectRoundTripRangeAndETag(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("objects", "erin", "")
	token := h.authorize("erin",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	content := []byte("hello world")
	digest := sha256Hex(content)
	key := "notes/greeting.txt"
	path := objectPath("objects", key)

	created := h.mustDo(t, http.MethodPut, path, token, content, map[string]string{
		"Content-Type":              "text/plain",
		"X-Filehouse-SHA256":        digest,
		"X-Filehouse-Meta-Campaign": "spring",
	})
	requireStatus(t, created, http.StatusCreated)
	object := decodeJSON[objectResponse](t, created)
	if object.Key != key || object.Size != int64(len(content)) {
		t.Fatalf("created object = %+v, want key %q size %d", object, key, len(content))
	}
	etag := quotedETag(content)
	if object.ETag != etag {
		t.Fatalf("etag = %q, want %q", object.ETag, etag)
	}
	if got := created.Header.Get("ETag"); got != etag {
		t.Fatalf("response ETag = %q, want %q", got, etag)
	}
	if got := created.Header.Get("X-Filehouse-SHA256"); got != digest {
		t.Fatalf("response sha256 = %q, want %q", got, digest)
	}

	fetched := h.mustDo(t, http.MethodGet, path, token, nil, nil)
	requireStatus(t, fetched, http.StatusOK)
	if !bytes.Equal(fetched.Body, content) {
		t.Fatalf("GET body = %q, want %q", fetched.Body, content)
	}
	if got := fetched.Header.Get("ETag"); got != etag {
		t.Fatalf("GET ETag = %q, want %q", got, etag)
	}
	if got := fetched.Header.Get("X-Filehouse-SHA256"); got != digest {
		t.Fatalf("GET sha256 = %q, want %q", got, digest)
	}
	if got := fetched.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("GET content type = %q, want text/plain", got)
	}
	if got := fetched.Header.Get("X-Filehouse-Meta-Campaign"); got != "spring" {
		t.Fatalf("GET metadata header = %q, want spring", got)
	}

	head := h.mustDo(t, http.MethodHead, path, token, nil, nil)
	requireStatus(t, head, http.StatusOK)
	if len(head.Body) != 0 {
		t.Fatalf("HEAD body = %q, want empty", head.Body)
	}
	if got := head.Header.Get("ETag"); got != etag {
		t.Fatalf("HEAD ETag = %q, want %q", got, etag)
	}

	ranged := h.mustDo(t, http.MethodGet, path, token, nil, map[string]string{"Range": "bytes=6-10"})
	requireStatus(t, ranged, http.StatusPartialContent)
	if string(ranged.Body) != "world" {
		t.Fatalf("range body = %q, want %q", ranged.Body, "world")
	}
	if got := ranged.Header.Get("Content-Range"); got != fmt.Sprintf("bytes 6-10/%d", len(content)) {
		t.Fatalf("Content-Range = %q", got)
	}

	bad := h.mustDo(t, http.MethodPut, objectPath("objects", "bad.bin"), token, content,
		map[string]string{"X-Filehouse-SHA256": strings.Repeat("0", 64)})
	requireProblem(t, bad, http.StatusUnprocessableEntity, "checksum_mismatch")
}

// TestContentDedupAndReaper covers (5): identical uploads share one blob at
// refcount 2 while logical usage counts both, and a reaper pass removes the
// blob after both objects are deleted.
func TestContentDedupAndReaper(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("dedup", "frank", "")
	token := h.authorize("frank",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"},
		iamfixture.Grant{Key: "filehouse:delete:own"})

	content := []byte("deduplicated payload")
	first := h.mustDo(t, http.MethodPut, objectPath("dedup", "one.bin"), token, content, nil)
	requireStatus(t, first, http.StatusCreated)
	second := h.mustDo(t, http.MethodPut, objectPath("dedup", "two.bin"), token, content, nil)
	requireStatus(t, second, http.StatusCreated)

	one := decodeJSON[objectResponse](t, first)
	two := decodeJSON[objectResponse](t, second)
	if one.BlobHash == "" || one.BlobHash != two.BlobHash {
		t.Fatalf("blob hashes differ: %q vs %q", one.BlobHash, two.BlobHash)
	}
	if refcount := h.blobRefcount(one.BlobHash); refcount != 2 {
		t.Fatalf("blob refcount = %d, want 2", refcount)
	}
	if rows := h.blobRowCount(); rows != 1 {
		t.Fatalf("blob rows = %d, want 1", rows)
	}
	bucket := h.bucketRow("dedup")
	if bucket.UsedBytes != int64(2*len(content)) || bucket.UsedObjects != 2 {
		t.Fatalf("logical usage = (%d bytes, %d objects), want (%d, 2)",
			bucket.UsedBytes, bucket.UsedObjects, 2*len(content))
	}
	if _, err := testSuite.blobs.Stat(one.BlobHash); err != nil {
		t.Fatalf("blob file missing before the reaper ran: %v", err)
	}

	requireStatus(t, h.mustDo(t, http.MethodDelete, objectPath("dedup", "one.bin"), token, nil, nil), http.StatusNoContent)
	requireStatus(t, h.mustDo(t, http.MethodDelete, objectPath("dedup", "two.bin"), token, nil, nil), http.StatusNoContent)
	if refcount := h.blobRefcount(one.BlobHash); refcount != 0 {
		t.Fatalf("blob refcount after deletes = %d, want 0", refcount)
	}
	if _, err := testSuite.blobs.Stat(one.BlobHash); err != nil {
		t.Fatalf("blob file removed before the reaper ran: %v", err)
	}
	if bucket := h.bucketRow("dedup"); bucket.UsedBytes != 0 || bucket.UsedObjects != 0 {
		t.Fatalf("usage after deletes = (%d, %d), want (0, 0)", bucket.UsedBytes, bucket.UsedObjects)
	}

	time.Sleep(100 * time.Millisecond)
	report, err := h.reaper.Once(context.Background())
	if err != nil {
		t.Fatalf("reaper pass: %v", err)
	}
	if report.BlobsDeleted != 1 {
		t.Fatalf("reaper deleted %d blobs, want 1", report.BlobsDeleted)
	}
	if rows := h.blobRowCount(); rows != 0 {
		t.Fatalf("blob rows after reap = %d, want 0", rows)
	}
	if _, err := testSuite.blobs.Stat(one.BlobHash); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("blob file after reap: err = %v, want ErrNotFound", err)
	}
}

// TestMultipartUploadFlow covers (6): init, staged parts, a mismatching part
// list (422), assembly and download, and the 404 after an abort.
func TestMultipartUploadFlow(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("multipart", "ivan", "")
	token := h.authorize("ivan",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	partOne := []byte("hello ")
	partTwo := []byte("world")
	total := append(append([]byte(nil), partOne...), partTwo...)

	initiated := h.sendJSON(t, http.MethodPost, "/api/v1/buckets/multipart/uploads", token, map[string]any{
		"key":          "assembled/greeting.txt",
		"content_type": "text/plain",
		"size":         len(total),
	}, nil)
	requireStatus(t, initiated, http.StatusCreated)
	upload := decodeJSON[initiateResponse](t, initiated)
	if upload.UploadID == "" {
		t.Fatal("upload_id is empty")
	}
	base := "/api/v1/buckets/multipart/uploads/" + upload.UploadID

	staged := h.mustDo(t, http.MethodPut, base+"/parts/1", token, partOne, nil)
	requireStatus(t, staged, http.StatusOK)
	firstPart := decodeJSON[partResponse](t, staged)
	if firstPart.PartNo != 1 || firstPart.Size != int64(len(partOne)) || firstPart.SHA256 != sha256Hex(partOne) {
		t.Fatalf("part 1 = %+v", firstPart)
	}
	requireStatus(t, h.mustDo(t, http.MethodPut, base+"/parts/2", token, partTwo, nil), http.StatusOK)

	detail := h.mustDo(t, http.MethodGet, base, token, nil, nil)
	requireStatus(t, detail, http.StatusOK)
	listed := decodeJSON[uploadDetail](t, detail)
	if listed.Key != "assembled/greeting.txt" || len(listed.Parts) != 2 {
		t.Fatalf("upload detail = %+v", listed)
	}
	if listed.Parts[0].PartNo != 1 || listed.Parts[1].PartNo != 2 {
		t.Fatalf("staged part numbers = %d, %d", listed.Parts[0].PartNo, listed.Parts[1].PartNo)
	}

	wrong := h.sendJSON(t, http.MethodPost, base+"/complete", token, map[string]any{"parts": []map[string]any{
		{"part_no": 1, "sha256": strings.Repeat("a", 64)},
		{"part_no": 2, "sha256": sha256Hex(partTwo)},
	}}, nil)
	requireProblem(t, wrong, http.StatusUnprocessableEntity, "part_mismatch")

	completed := h.sendJSON(t, http.MethodPost, base+"/complete", token, map[string]any{"parts": []map[string]any{
		{"part_no": 1, "sha256": sha256Hex(partOne)},
		{"part_no": 2, "sha256": sha256Hex(partTwo)},
	}}, nil)
	requireStatus(t, completed, http.StatusCreated)
	object := decodeJSON[objectResponse](t, completed)
	if object.Key != "assembled/greeting.txt" || object.Size != int64(len(total)) {
		t.Fatalf("completed object = %+v", object)
	}
	if object.ETag != quotedETag(total) {
		t.Fatalf("completed etag = %q, want %q", object.ETag, quotedETag(total))
	}

	downloaded := h.mustDo(t, http.MethodGet, objectPath("multipart", "assembled/greeting.txt"), token, nil, nil)
	requireStatus(t, downloaded, http.StatusOK)
	if !bytes.Equal(downloaded.Body, total) {
		t.Fatalf("assembled download = %q, want %q", downloaded.Body, total)
	}

	aborted := h.sendJSON(t, http.MethodPost, "/api/v1/buckets/multipart/uploads", token,
		map[string]any{"key": "aborted.bin"}, nil)
	requireStatus(t, aborted, http.StatusCreated)
	abortID := decodeJSON[initiateResponse](t, aborted).UploadID
	abortBase := "/api/v1/buckets/multipart/uploads/" + abortID
	requireStatus(t, h.mustDo(t, http.MethodDelete, abortBase, token, nil, nil), http.StatusNoContent)
	requireProblem(t, h.mustDo(t, http.MethodGet, abortBase, token, nil, nil),
		http.StatusNotFound, "upload_not_found")
	requireProblem(t, h.sendJSON(t, http.MethodPost, abortBase+"/complete", token, map[string]any{"parts": []any{}}, nil),
		http.StatusNotFound, "upload_not_found")
}

// TestBucketQuotaExceeded covers (7): a write above the bucket quota fails with
// 413 and leaves every counter untouched; a fitting write still succeeds.
func TestBucketQuotaExceeded(t *testing.T) {
	h := newHarness(t)
	if _, err := testSuite.store.CreateBucket(context.Background(), store.Bucket{
		Name:       "quota",
		OwnerID:    "gina",
		OwnerKind:  "user",
		QuotaBytes: 4,
	}); err != nil {
		t.Fatalf("seed quota bucket: %v", err)
	}
	token := h.authorize("gina",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	requireProblem(t, h.mustDo(t, http.MethodPut, objectPath("quota", "big.bin"), token, []byte("1234567890"), nil),
		http.StatusRequestEntityTooLarge, "quota_exceeded")

	unchanged := h.bucketRow("quota")
	if unchanged.UsedBytes != 0 || unchanged.UsedObjects != 0 {
		t.Fatalf("counters after rejection = (%d, %d), want (0, 0)", unchanged.UsedBytes, unchanged.UsedObjects)
	}
	if rows := h.blobRowCount(); rows != 0 {
		t.Fatalf("blob rows after rejection = %d, want 0", rows)
	}

	requireStatus(t, h.mustDo(t, http.MethodPut, objectPath("quota", "fits.bin"), token, []byte("1234"), nil),
		http.StatusCreated)
	final := h.bucketRow("quota")
	if final.UsedBytes != 4 || final.UsedObjects != 1 {
		t.Fatalf("counters after fitting write = (%d, %d), want (4, 1)", final.UsedBytes, final.UsedObjects)
	}
}

// TestPresignedURLFlow covers (8): mint and redeem, tampered signature (403),
// expired token (410) and a perm_ver bump after minting (403 on an instance
// whose permission cache has not seen the old version).
func TestPresignedURLFlow(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("share", "gina", "")
	token := h.authorize("gina",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"},
		iamfixture.Grant{Key: "filehouse:share:own"})

	content := []byte("shared bytes")
	requireStatus(t, h.mustDo(t, http.MethodPut, objectPath("share", "report.txt"), token, content, nil),
		http.StatusCreated)

	mint := func(ttl int) presignResponse {
		t.Helper()
		response := h.sendJSON(t, http.MethodPost, "/api/v1/presign", token, map[string]any{
			"bucket": "share", "key": "report.txt", "method": "GET", "ttl_seconds": ttl,
		}, nil)
		requireStatus(t, response, http.StatusOK)
		minted := decodeJSON[presignResponse](t, response)
		if minted.URL == "" || minted.Method != "GET" || minted.Bucket != "share" || minted.Key != "report.txt" {
			t.Fatalf("mint response = %+v", minted)
		}
		return minted
	}

	redeem := func(raw string) result {
		t.Helper()
		return h.mustDo(t, http.MethodGet, requestPath(t, raw), "", nil, nil)
	}

	minted := mint(600)
	allowed := redeem(minted.URL)
	requireStatus(t, allowed, http.StatusOK)
	if !bytes.Equal(allowed.Body, content) {
		t.Fatalf("presigned download = %q, want %q", allowed.Body, content)
	}

	requireProblem(t, redeem(tamperSignature(t, minted.URL)), http.StatusForbidden, "presign_invalid")

	expiring := mint(1)
	time.Sleep(1200 * time.Millisecond)
	requireProblem(t, redeem(expiring.URL), http.StatusGone, "presign_expired")

	// The minted token embeds perm_ver 1. Bumping the subject's permission
	// version invalidates it: a redemption through an instance whose permission
	// cache has not seen version 1 must reject the stale signature.
	stale := mint(600)
	requireStatus(t, redeem(stale.URL), http.StatusOK)
	if bumped := h.fixture.BumpPermVer("gina"); bumped != 2 {
		t.Fatalf("permission version after bump = %d, want 2", bumped)
	}
	instance := h.freshInstance()
	problem := requireProblem(t,
		h.doAgainst(t, instance.URL, http.MethodGet, requestPath(t, stale.URL), "", nil, nil),
		http.StatusForbidden, "insufficient_permissions")
	if !strings.Contains(problem.Reason, "permissions changed") {
		t.Fatalf("403 reason = %q, want a permissions-changed reason", problem.Reason)
	}
}

// TestObjectListCursorPagination covers (9): three pages of two, two and one
// object with the cursor only empty on the last page.
func TestObjectListCursorPagination(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("paging", "henry", "")
	token := h.authorize("henry",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	keys := []string{"item-01", "item-02", "item-03", "item-04", "item-05"}
	for _, key := range keys {
		requireStatus(t, h.mustDo(t, http.MethodPut, objectPath("paging", key), token, []byte(key), nil),
			http.StatusCreated)
	}

	page := func(cursor string) objectPage {
		t.Helper()
		path := "/api/v1/buckets/paging/objects?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		response := h.mustDo(t, http.MethodGet, path, token, nil, nil)
		requireStatus(t, response, http.StatusOK)
		return decodeJSON[objectPage](t, response)
	}

	first := page("")
	if len(first.Items) != 2 || first.Items[0].Key != keys[0] || first.Items[1].Key != keys[1] {
		t.Fatalf("page 1 keys = %v", itemKeys(first.Items))
	}
	if first.NextCursor == "" {
		t.Fatal("page 1 has no next_cursor")
	}
	second := page(first.NextCursor)
	if len(second.Items) != 2 || second.Items[0].Key != keys[2] || second.Items[1].Key != keys[3] {
		t.Fatalf("page 2 keys = %v", itemKeys(second.Items))
	}
	if second.NextCursor == "" {
		t.Fatal("page 2 has no next_cursor")
	}
	third := page(second.NextCursor)
	if len(third.Items) != 1 || third.Items[0].Key != keys[4] {
		t.Fatalf("page 3 keys = %v", itemKeys(third.Items))
	}
	if third.NextCursor != "" {
		t.Fatalf("page 3 next_cursor = %q, want empty", third.NextCursor)
	}

	requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/buckets/paging/objects?cursor=not-a-cursor", token, nil, nil),
		http.StatusBadRequest, "invalid_request")
}

func itemKeys(items []objectResponse) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
	}
	return keys
}

// TestIdempotencyReplay covers (10): replaying a POST with the same
// Idempotency-Key returns the stored response with Idempotency-Replayed: true,
// while a different body is a 422 conflict.
func TestIdempotencyReplay(t *testing.T) {
	h := newHarness(t)
	token := h.authorize("ida", iamfixture.Grant{Key: "filehouse:write:own"})
	headers := map[string]string{"Idempotency-Key": "create-bucket-1"}

	first := h.sendJSON(t, http.MethodPost, "/api/v1/buckets", token, map[string]any{"name": "idempotent-bucket"}, headers)
	requireStatus(t, first, http.StatusCreated)
	if replayed := first.Header.Get("Idempotency-Replayed"); replayed != "" {
		t.Fatalf("first response carries Idempotency-Replayed: %q", replayed)
	}

	second := h.sendJSON(t, http.MethodPost, "/api/v1/buckets", token, map[string]any{"name": "idempotent-bucket"}, headers)
	requireStatus(t, second, http.StatusCreated)
	if replayed := second.Header.Get("Idempotency-Replayed"); replayed != "true" {
		t.Fatalf("replay header = %q, want true", replayed)
	}
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatalf("replay body = %s, want %s", truncateBody(second.Body), truncateBody(first.Body))
	}

	conflict := h.sendJSON(t, http.MethodPost, "/api/v1/buckets", token, map[string]any{"name": "other-bucket"}, headers)
	requireProblem(t, conflict, http.StatusUnprocessableEntity, "idempotency_conflict")
}

// TestAdminEndpointsRequireManageGrant covers (11): stats and quota management
// succeed with manage:any and are 403 without it.
func TestAdminEndpointsRequireManageGrant(t *testing.T) {
	h := newHarness(t)
	h.seedBucket("admin-visible", "alice", "")
	admin := h.authorize("admin", iamfixture.Grant{Key: "filehouse:manage:any"})

	statsResponse := h.mustDo(t, http.MethodGet, "/api/v1/admin/stats", admin, nil, nil)
	requireStatus(t, statsResponse, http.StatusOK)
	stats := decodeJSON[map[string]any](t, statsResponse)
	for _, field := range []string{"buckets", "objects", "blobs", "physical_blobs"} {
		if _, present := stats[field]; !present {
			t.Fatalf("stats response misses %q: %s", field, truncateBody(statsResponse.Body))
		}
	}
	if stats["buckets"].(float64) != 1 {
		t.Fatalf("stats buckets = %v, want 1", stats["buckets"])
	}

	listed := h.mustDo(t, http.MethodGet, "/api/v1/admin/quotas", admin, nil, nil)
	requireStatus(t, listed, http.StatusOK)
	decodeJSON[quotaPage](t, listed)

	put := h.sendJSON(t, http.MethodPut, "/api/v1/admin/quotas/user/harry", admin,
		map[string]any{"max_bytes": 1 << 20, "max_objects": 5}, nil)
	requireStatus(t, put, http.StatusOK)
	quota := decodeJSON[quotaResponse](t, put)
	if quota.SubjectKind != "user" || quota.SubjectID != "harry" || quota.MaxBytes != 1<<20 || quota.MaxObjects != 5 {
		t.Fatalf("stored quota = %+v", quota)
	}
	stored, found, err := testSuite.store.GetQuota(context.Background(), "user", "harry")
	if err != nil || !found {
		t.Fatalf("read quota back: found=%v err=%v", found, err)
	}
	if stored.MaxBytes != 1<<20 || stored.MaxObjects != 5 {
		t.Fatalf("quota row = %+v", stored)
	}

	nobody := h.authorize("nobody", iamfixture.Grant{Key: "filehouse:read:any"})
	requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/admin/stats", nobody, nil, nil),
		http.StatusForbidden, "insufficient_permissions")
	requireProblem(t, h.mustDo(t, http.MethodGet, "/api/v1/admin/quotas", nobody, nil, nil),
		http.StatusForbidden, "insufficient_permissions")
	requireProblem(t, h.sendJSON(t, http.MethodPut, "/api/v1/admin/quotas/user/nobody", nobody,
		map[string]any{"max_bytes": 1, "max_objects": 1}, nil),
		http.StatusForbidden, "insufficient_permissions")
}

// TestOrphanBlobReclaim covers (12): an upload rejected by the bucket quota
// after its blob file was already written is reclaimed by the reaper's orphan
// sweep, while a blob that an object still references is never swept.
func TestOrphanBlobReclaim(t *testing.T) {
	h := newHarness(t)
	if _, err := testSuite.store.CreateBucket(context.Background(), store.Bucket{
		Name:       "orphans",
		OwnerID:    "lena",
		OwnerKind:  "user",
		QuotaBytes: 16,
	}); err != nil {
		t.Fatalf("seed quota bucket: %v", err)
	}
	token := h.authorize("lena",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	// Normalise the blob directory: the tables were just truncated, so every
	// file left behind by an earlier test is an orphan with no row. One pass
	// with zero grace sweeps them, letting the assertions below count exactly
	// what this test writes.
	if _, err := h.reaper.Once(context.Background()); err != nil {
		t.Fatalf("normalising reaper pass: %v", err)
	}
	if files := h.blobFileCount(); files != 0 {
		t.Fatalf("blob files after the normalising pass = %d, want 0", files)
	}

	// Two objects share one live blob (5 bytes each, refcount 2), using 10 of
	// the 16 quota bytes.
	live := []byte("live!")
	requireStatus(t, h.mustDo(t, http.MethodPut, objectPath("orphans", "live.bin"), token, live, nil),
		http.StatusCreated)
	requireStatus(t, h.mustDo(t, http.MethodPut, objectPath("orphans", "live-copy.bin"), token, live, nil),
		http.StatusCreated)
	liveHash := sha256Hex(live)
	if refcount := h.blobRefcount(liveHash); refcount != 2 {
		t.Fatalf("live blob refcount = %d, want 2", refcount)
	}

	// A 10-byte upload no longer fits (10 + 10 > 16) and is rejected after its
	// content was written to the blob directory.
	rejected := []byte("0123456789")
	requireProblem(t, h.mustDo(t, http.MethodPut, objectPath("orphans", "rejected.bin"), token, rejected, nil),
		http.StatusRequestEntityTooLarge, "quota_exceeded")
	rejectedHash := sha256Hex(rejected)
	if rows := h.blobRowCount(); rows != 1 {
		t.Fatalf("blob rows after rejection = %d, want 1", rows)
	}
	if _, err := testSuite.blobs.Stat(rejectedHash); err != nil && !errors.Is(err, blob.ErrNotFound) {
		// The handler cleanup may already have released the file; either end
		// state is accepted here and asserted after the pass below.
		t.Fatalf("stat rejected blob after the response: %v", err)
	}

	// Let the clock move past the rejected file's modification time: a
	// zero-grace pass only sweeps files strictly older than its start time.
	time.Sleep(100 * time.Millisecond)
	report, err := h.reaper.Once(context.Background())
	if err != nil {
		t.Fatalf("reaper pass: %v", err)
	}
	if report.OrphanFilesDeleted != 1 {
		t.Fatalf("orphan files deleted = %d, want 1", report.OrphanFilesDeleted)
	}
	if report.OrphanBytesDeleted != int64(len(rejected)) {
		t.Fatalf("orphan bytes deleted = %d, want %d", report.OrphanBytesDeleted, len(rejected))
	}
	if _, err := testSuite.blobs.Stat(rejectedHash); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("rejected blob file after reap: err = %v, want ErrNotFound", err)
	}
	if files, rows := h.blobFileCount(), h.blobRowCount(); files != rows {
		t.Fatalf("blob files = %d, blob rows = %d, want equal", files, rows)
	}

	// The shared live blob survives the sweep and both objects still download
	// byte-identically.
	if _, err := testSuite.blobs.Stat(liveHash); err != nil {
		t.Fatalf("live blob file after reap: %v", err)
	}
	if refcount := h.blobRefcount(liveHash); refcount != 2 {
		t.Fatalf("live blob refcount after reap = %d, want 2", refcount)
	}
	for _, key := range []string{"live.bin", "live-copy.bin"} {
		downloaded := h.mustDo(t, http.MethodGet, objectPath("orphans", key), token, nil, nil)
		requireStatus(t, downloaded, http.StatusOK)
		if !bytes.Equal(downloaded.Body, live) {
			t.Fatalf("%s download = %q, want %q", key, downloaded.Body, live)
		}
	}

	// The admin GC endpoint embeds the pass report, so the orphan counters are
	// part of its response.
	admin := h.authorize("admin", iamfixture.Grant{Key: "filehouse:manage:any"})
	gcResponse := h.sendJSON(t, http.MethodPost, "/api/v1/admin/gc", admin, nil, nil)
	requireStatus(t, gcResponse, http.StatusOK)
	gcReport := decodeJSON[map[string]any](t, gcResponse)
	for _, field := range []string{"orphan_files_deleted", "orphan_bytes_deleted"} {
		if _, present := gcReport[field]; !present {
			t.Fatalf("admin gc response misses %q: %s", field, truncateBody(gcResponse.Body))
		}
	}
}

// TestOrphanSweepContinuesPastPage covers (13): the orphan sweep resumes after
// the last file a bounded pass saw, so an orphan that sorts past the first page
// is still reached on later passes, and the walk wraps back to the top once the
// directory is exhausted.
func TestOrphanSweepContinuesPastPage(t *testing.T) {
	h := newHarness(t)
	// Normalise the shared blob directory so the page arithmetic below counts
	// only the files this test writes.
	if _, err := h.reaper.Once(context.Background()); err != nil {
		t.Fatalf("normalising reaper pass: %v", err)
	}
	if files := h.blobFileCount(); files != 0 {
		t.Fatalf("blob files after the normalising pass = %d, want 0", files)
	}

	h.seedBucket("paged", "mia", "")
	token := h.authorize("mia",
		iamfixture.Grant{Key: "filehouse:read:own"},
		iamfixture.Grant{Key: "filehouse:write:own"})

	// Five live objects. Their blobs are never deleted, so they form a barrier
	// that a walk restarting from the top can never see past.
	const liveCount = 5
	liveContents := make([][]byte, 0, liveCount)
	liveHashes := make([]string, 0, liveCount)
	for i := range liveCount {
		content := []byte(fmt.Sprintf("live-%d", i))
		requireStatus(t, h.mustDo(t, http.MethodPut,
			objectPath("paged", fmt.Sprintf("live-%d.bin", i)), token, content, nil), http.StatusCreated)
		liveContents = append(liveContents, content)
		liveHashes = append(liveHashes, sha256Hex(content))
	}

	// The tail orphan sorts after every live hash: it uses the maximum digest,
	// and no real sha256 equals it. With a page of four it can only be reached
	// by a resumed walk.
	tail := strings.Repeat("f", 64)
	h.writeBlobFile(tail, []byte("tail orphan"))
	// Let the clock move past the planted file's modification time: a zero-grace
	// pass only sweeps files strictly older than its start time.
	time.Sleep(100 * time.Millisecond)

	reaper := gc.New(testSuite.store, testSuite.blobs, testSuite.logger,
		gc.Config{Interval: time.Hour, OrphanScanLimit: 4})

	// The first page is filled entirely by live blobs, so nothing is deleted
	// and the tail orphan must survive.
	firstPage, err := reaper.Once(context.Background())
	if err != nil {
		t.Fatalf("first paged pass: %v", err)
	}
	if firstPage.OrphanFilesDeleted != 0 {
		t.Fatalf("first page deleted %d orphans, want 0 (it only holds live blobs)", firstPage.OrphanFilesDeleted)
	}
	if _, err := testSuite.blobs.Stat(tail); err != nil {
		t.Fatalf("tail orphan gone on the first page: %v", err)
	}

	// The second pass resumes after the live blobs and reaches the tail orphan.
	second, err := reaper.Once(context.Background())
	if err != nil {
		t.Fatalf("second paged pass: %v", err)
	}
	if second.OrphanFilesDeleted != 1 {
		t.Fatalf("second page deleted %d orphans, want 1", second.OrphanFilesDeleted)
	}
	if _, err := testSuite.blobs.Stat(tail); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("tail orphan after the resumed pass: err = %v, want ErrNotFound", err)
	}

	// The exhausted walk wrapped back to the top: an orphan planted afterwards
	// that sorts before the previous cursor is found by the next pass.
	wrapped := strings.Repeat("0", 62) + "ce"
	h.writeBlobFile(wrapped, []byte("late orphan"))
	time.Sleep(100 * time.Millisecond)
	third, err := reaper.Once(context.Background())
	if err != nil {
		t.Fatalf("wrap-around pass: %v", err)
	}
	if third.OrphanFilesDeleted != 1 {
		t.Fatalf("wrap-around pass deleted %d orphans, want 1", third.OrphanFilesDeleted)
	}
	if _, err := testSuite.blobs.Stat(wrapped); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("late orphan after the wrap-around pass: err = %v, want ErrNotFound", err)
	}

	// Every live blob, its row and its downloads survived every pass.
	for i, hash := range liveHashes {
		if _, err := testSuite.blobs.Stat(hash); err != nil {
			t.Fatalf("live blob %d file after the sweeps: %v", i, err)
		}
		if refcount := h.blobRefcount(hash); refcount != 1 {
			t.Fatalf("live blob %d refcount after the sweeps = %d, want 1", i, refcount)
		}
		downloaded := h.mustDo(t, http.MethodGet, objectPath("paged", fmt.Sprintf("live-%d.bin", i)), token, nil, nil)
		requireStatus(t, downloaded, http.StatusOK)
		if !bytes.Equal(downloaded.Body, liveContents[i]) {
			t.Fatalf("live-%d.bin download = %q, want %q", i, downloaded.Body, liveContents[i])
		}
	}
}
