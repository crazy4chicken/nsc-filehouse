package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"
	"github.com/go-chi/chi/v5"

	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// Permission actions, scopes and the resource segment of the filehouse
// catalog (§1). "*" matches exactly one segment.
const (
	verbRead   = "read"
	verbWrite  = "write"
	verbDelete = "delete"

	scopeOwn  = "own"
	scopeTeam = "team"
	scopeAny  = "any"

	wildcardSegment = "*"

	permissionResource = "filehouse"
)

// Pagination bounds of the HTTP surface (§0): default 100, maximum 1000.
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// bucketNamePattern is the contract bucket grammar (§5).
var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// claimsFor returns the verified claims of the authenticated request. It writes
// the 401 problem itself when the request carries no usable bearer token.
func (s *Server) claimsFor(w http.ResponseWriter, r *http.Request) (iam.Claims, bool) {
	if s.Authorizer() == nil {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "", "invalid_token")
		return iam.Claims{}, false
	}
	claims, ok := s.Authorizer().Claims(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "", "invalid_token")
		return iam.Claims{}, false
	}
	return claims, true
}

// deny writes the 403 problem of a cascade denial. The reason names the
// permission keys the cascade attempted and never carries credentials.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, reason string) {
	httpx.WriteProblemReason(w, r, http.StatusForbidden, http.StatusText(http.StatusForbidden), "insufficient_permissions", reason)
}

// authorize runs the scope cascade for one resource and writes the failure
// response itself: 503 iam_unavailable when no decision can be made and 403
// insufficient_permissions when the cascade denies.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, claims iam.Claims, verb string, resource iam.Resource) bool {
	if s.Authorizer() == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return false
	}
	allowed, reason, err := s.Authorizer().Decide(r.Context(), claims, verb, resource)
	if err != nil {
		s.log.Error("authorization decision failed", "error", err, "verb", verb)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return false
	}
	if !allowed {
		s.deny(w, r, reason)
		return false
	}
	return true
}

// decideAny requires a platform wide (":any") grant. The resource context is
// deliberately empty so the cascade only attempts the any scope key.
func (s *Server) decideAny(w http.ResponseWriter, r *http.Request, claims iam.Claims, verb string) bool {
	return s.authorize(w, r, claims, verb, iam.Resource{})
}

// bucketResource builds the resource context of a bucket. Every decision that
// starts from a bucket passes the same owner/team/attrs triple, so a cascade
// denial cannot be skipped by resubmitting the operation with a different
// context. extra carries the operation specific attributes (key, size, ...).
func bucketResource(bucket store.Bucket, extra map[string]any) iam.Resource {
	attrs := make(map[string]any, len(extra)+1)
	for name, value := range extra {
		attrs[name] = value
	}
	attrs["bucket"] = bucket.Name
	return iam.Resource{OwnerID: bucket.OwnerID, TeamID: bucket.TeamID, Attrs: attrs}
}

// validateBucketName enforces the contract bucket grammar (§5).
func validateBucketName(name string) error {
	if !bucketNamePattern.MatchString(name) {
		return errors.New("bucket name must match ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
	}
	return nil
}

// bucketByName resolves a bucket by its unique name. It writes its own errors
// and performs no authorization.
func (s *Server) bucketByName(w http.ResponseWriter, r *http.Request, name string) (store.Bucket, bool) {
	if err := validateBucketName(name); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_bucket_name")
		return store.Bucket{}, false
	}
	bucket, err := s.Store().GetBucketByName(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "bucket_not_found")
			return store.Bucket{}, false
		}
		s.log.Error("load bucket failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return store.Bucket{}, false
	}
	return bucket, true
}

// bucketFor resolves the {bucket} route parameter, see bucketByName.
func (s *Server) bucketFor(w http.ResponseWriter, r *http.Request) (store.Bucket, bool) {
	return s.bucketByName(w, r, chi.URLParam(r, "bucket"))
}

// decodeRequestBody decodes a size limited JSON body and writes the problem
// response itself (413 payload_too_large or 400 invalid_request).
func decodeRequestBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := httpx.DecodeJSON(w, r, dst)
	if err == nil {
		return true
	}
	if errors.Is(err, httpx.ErrBodyTooLarge) {
		httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "payload_too_large")
		return false
	}
	httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
	return false
}

// parsePageLimit reads the ?limit= bound. Empty means "store default"; a
// negative or unparsable value is a 400 invalid_request.
func parsePageLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 0, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return 0, false
	}
	return limit, true
}

// effectiveLimit projects a ?limit= bound onto the contract page bounds,
// mirroring the store clamp (default 100, maximum 1000).
func effectiveLimit(limit int) int {
	switch {
	case limit <= 0:
		return defaultPageLimit
	case limit > maxPageLimit:
		return maxPageLimit
	default:
		return limit
	}
}

// limits returns the configured bounds; a server without a configuration serves
// the zero bounds (unlimited).
func (s *Server) limits() config.LimitsConfig {
	if s.Config() == nil {
		return config.LimitsConfig{}
	}
	return s.Config().Limits
}

// subjectKind is the subject kind recorded for a caller; the verified token
// kind is authoritative and defaults to "user".
func subjectKind(claims iam.Claims) string {
	if claims.Kind != "" {
		return claims.Kind
	}
	return "user"
}

// grantsAllow reports whether grants holds an allow whose resource, action and
// scope segments cover the requested permission; "*" matches one segment.
func grantsAllow(grants []iam.Permission, action, scope string) bool {
	for _, grant := range grants {
		if grant.Deny {
			continue
		}
		if segmentMatches(grant.Resource, permissionResource) &&
			segmentMatches(grant.Action, action) &&
			segmentMatches(grant.Scope, scope) {
			return true
		}
	}
	return false
}

func segmentMatches(grant, requested string) bool {
	return grant == wildcardSegment || grant == requested
}

// bucketPage is the paginated bucket listing envelope.
type bucketPage struct {
	Items      []store.Bucket `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

type createBucketRequest struct {
	Name         string `json:"name"`
	TeamID       string `json:"team_id"`
	Description  string `json:"description"`
	QuotaBytes   *int64 `json:"quota_bytes"`
	QuotaObjects *int64 `json:"quota_objects"`
}

// handleCreateBucket creates a bucket owned by the caller. Write permission is
// decided against the prospective bucket: owner = caller, team = body team.
func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	var body createBucketRequest
	if !decodeRequestBody(w, r, &body) {
		return
	}
	if err := validateBucketName(body.Name); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_bucket_name")
		return
	}
	if (body.QuotaBytes != nil && *body.QuotaBytes < 0) || (body.QuotaObjects != nil && *body.QuotaObjects < 0) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	limits := s.limits()
	bucket := store.Bucket{
		Name:         body.Name,
		OwnerID:      claims.Subject,
		OwnerKind:    subjectKind(claims),
		TeamID:       body.TeamID,
		Description:  body.Description,
		QuotaBytes:   limits.BucketDefaultQuotaBytes,
		QuotaObjects: limits.BucketDefaultQuotaObjects,
	}
	if body.QuotaBytes != nil {
		bucket.QuotaBytes = *body.QuotaBytes
	}
	if body.QuotaObjects != nil {
		bucket.QuotaObjects = *body.QuotaObjects
	}
	resource := iam.Resource{
		OwnerID: claims.Subject,
		TeamID:  body.TeamID,
		Attrs:   map[string]any{"bucket": body.Name},
	}
	if !s.authorize(w, r, claims, verbWrite, resource) {
		return
	}
	created, err := s.Store().CreateBucket(r.Context(), bucket)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteProblem(w, r, http.StatusConflict, "", "bucket_exists")
			return
		}
		s.log.Error("create bucket failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// handleGetBucket returns one bucket the caller may read.
func (s *Server) handleGetBucket(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	if !s.authorize(w, r, claims, verbRead, bucketResource(bucket, nil)) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, bucket)
}

type patchBucketRequest struct {
	Description  *string `json:"description"`
	QuotaBytes   *int64  `json:"quota_bytes"`
	QuotaObjects *int64  `json:"quota_objects"`
}

// handlePatchBucket updates the mutable bucket attributes. Description changes
// require write on the bucket; quota changes additionally require the platform
// wide manage grant, because a quota bounds every future writer of the bucket.
func (s *Server) handlePatchBucket(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	var body patchBucketRequest
	if !decodeRequestBody(w, r, &body) {
		return
	}
	if body.Description == nil && body.QuotaBytes == nil && body.QuotaObjects == nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	if (body.QuotaBytes != nil && *body.QuotaBytes < 0) || (body.QuotaObjects != nil && *body.QuotaObjects < 0) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	if !s.authorize(w, r, claims, verbWrite, bucketResource(bucket, nil)) {
		return
	}
	if body.QuotaBytes != nil || body.QuotaObjects != nil {
		if !s.decideAny(w, r, claims, "manage") {
			return
		}
	}
	updated := bucket
	if body.Description != nil {
		updated.Description = *body.Description
	}
	if body.QuotaBytes != nil {
		updated.QuotaBytes = *body.QuotaBytes
	}
	if body.QuotaObjects != nil {
		updated.QuotaObjects = *body.QuotaObjects
	}
	out, err := s.Store().UpdateBucket(r.Context(), updated)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "bucket_not_found")
			return
		}
		s.log.Error("update bucket failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// handleDeleteBucket removes an empty bucket.
func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	if !s.authorize(w, r, claims, verbDelete, bucketResource(bucket, nil)) {
		return
	}
	err := s.Store().DeleteBucket(r.Context(), bucket.ID)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrBucketNotEmpty):
		httpx.WriteProblem(w, r, http.StatusConflict, "", "bucket_not_empty")
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "", "bucket_not_found")
	default:
		s.log.Error("delete bucket failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
	}
}

// handleListBuckets lists the buckets the caller may read. The cascade cannot
// filter rows, so the candidate set is derived from the caller's effective
// grants and every candidate is re-verified with Decide. A candidate the
// cascade denies is dropped from the page (fail-closed): grants may be
// conditional, so the coarse filter never substitutes for the real decision.
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	limit, ok := parsePageLimit(w, r)
	if !ok {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	grants, err := s.Authorizer().Grants(r.Context(), claims)
	if err != nil {
		s.log.Error("load permission grants failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return
	}
	anyRead := grantsAllow(grants, verbRead, scopeAny)
	ownRead := grantsAllow(grants, verbRead, scopeOwn)
	teamRead := grantsAllow(grants, verbRead, scopeTeam) && claims.Team != ""
	switch {
	case anyRead:
		// Platform wide read: no candidate filter is needed.
		s.listBuckets(w, r, claims, store.BucketFilter{}, limit, cursor)
	case ownRead && teamRead:
		s.listMergedBuckets(w, r, claims, limit, cursor)
	case ownRead:
		s.listBuckets(w, r, claims, store.BucketFilter{OwnerID: claims.Subject}, limit, cursor)
	case teamRead:
		s.listBuckets(w, r, claims, store.BucketFilter{TeamID: claims.Team}, limit, cursor)
	default:
		// No read grant can match a candidate row. Decide on an empty resource
		// so the caller receives the cascade reason for the denial.
		s.authorize(w, r, claims, verbRead, iam.Resource{})
	}
}

// listBuckets serves one filtered store query. Because a page always comes from
// the same filter scope, the store cursor is passed through untouched.
func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request, claims iam.Claims, filter store.BucketFilter, limit int, cursor string) {
	filter.Limit = limit
	filter.Cursor = cursor
	items, next, err := s.Store().ListBuckets(r.Context(), filter)
	if err != nil {
		s.writeListingFailure(w, r, err)
		return
	}
	page := make([]store.Bucket, 0, len(items))
	for _, bucket := range items {
		allowed, ok := s.authorizeBucketRow(w, r, claims, bucket)
		if !ok {
			return
		}
		if allowed {
			page = append(page, bucket)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, bucketPage{Items: page, NextCursor: next})
}

// authorizeBucketRow re-runs the read cascade for one listing candidate. A
// decision error is written as 503 and reported with ok = false; a plain denial
// returns allowed = false and drops the row.
func (s *Server) authorizeBucketRow(w http.ResponseWriter, r *http.Request, claims iam.Claims, bucket store.Bucket) (allowed, ok bool) {
	allowed, reason, err := s.Authorizer().Decide(r.Context(), claims, verbRead, bucketResource(bucket, nil))
	if err != nil {
		s.log.Error("authorization decision failed", "error", err, "verb", verbRead)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return false, false
	}
	if !allowed {
		s.log.Debug("bucket listing dropped a denied candidate", "bucket", bucket.Name, "reason", reason)
	}
	return allowed, true
}

// writeListingFailure maps a store listing error onto a problem response.
func (s *Server) writeListingFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrInvalidCursor) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	s.log.Error("list buckets failed", "error", err)
	httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
}

// bucketStream pulls one name ordered bucket scan lazily, skipping every name a
// previous merged page already examined.
type bucketStream struct {
	store     *store.Store
	filter    store.BucketFilter
	marker    string
	page      []store.Bucket
	cursor    string
	exhausted bool
}

func newBucketStream(st *store.Store, filter store.BucketFilter, marker string, window int) *bucketStream {
	filter.Limit = window
	return &bucketStream{store: st, filter: filter, marker: marker}
}

// next returns the following bucket, or ok = false when the source is drained.
func (bs *bucketStream) next(ctx context.Context) (store.Bucket, bool, error) {
	for len(bs.page) == 0 {
		if bs.exhausted {
			return store.Bucket{}, false, nil
		}
		filter := bs.filter
		filter.Cursor = bs.cursor
		items, cursor, err := bs.store.ListBuckets(ctx, filter)
		if err != nil {
			return store.Bucket{}, false, err
		}
		for _, bucket := range items {
			if bucket.Name > bs.marker {
				bs.page = append(bs.page, bucket)
			}
		}
		bs.cursor = cursor
		bs.exhausted = cursor == ""
	}
	bucket := bs.page[0]
	bs.page = bs.page[1:]
	return bucket, true, nil
}

// listMergedBuckets serves callers holding both an own and a team read grant.
// The two candidate queries are name ordered, so their pages are merged by name
// and deduplicated (a bucket can be owned by the caller and attached to the
// caller's team at once). Store cursors are bound to one filter scope and cannot
// address a merged result set, so merged pages paginate on our own cursor
// carrying the last examined name, and each filtered scan resumes from the
// start of its source skipping the names that were already examined. Bucket
// counts per subject are small, and this keeps page boundaries exact without
// re-emitting denied rows.
func (s *Server) listMergedBuckets(w http.ResponseWriter, r *http.Request, claims iam.Claims, limit int, cursor string) {
	marker, err := httpx.DecodeCursor(cursor)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	ctx := r.Context()
	pageSize := effectiveLimit(limit)
	owner := newBucketStream(s.Store(), store.BucketFilter{OwnerID: claims.Subject}, marker, pageSize)
	team := newBucketStream(s.Store(), store.BucketFilter{TeamID: claims.Team}, marker, pageSize)
	ownerItem, ownerOK, err := owner.next(ctx)
	if err != nil {
		s.writeListingFailure(w, r, err)
		return
	}
	teamItem, teamOK, err := team.next(ctx)
	if err != nil {
		s.writeListingFailure(w, r, err)
		return
	}
	page := make([]store.Bucket, 0, pageSize)
	var last string
	for len(page) < pageSize {
		var candidate store.Bucket
		switch {
		case ownerOK && teamOK:
			switch {
			case ownerItem.Name < teamItem.Name:
				candidate = ownerItem
				if ownerItem, ownerOK, err = owner.next(ctx); err != nil {
					s.writeListingFailure(w, r, err)
					return
				}
			case teamItem.Name < ownerItem.Name:
				candidate = teamItem
				if teamItem, teamOK, err = team.next(ctx); err != nil {
					s.writeListingFailure(w, r, err)
					return
				}
			default:
				// Same bucket through both filters: emit it once and step both.
				candidate = ownerItem
				if ownerItem, ownerOK, err = owner.next(ctx); err != nil {
					s.writeListingFailure(w, r, err)
					return
				}
				if teamItem, teamOK, err = team.next(ctx); err != nil {
					s.writeListingFailure(w, r, err)
					return
				}
			}
		case ownerOK:
			candidate = ownerItem
			if ownerItem, ownerOK, err = owner.next(ctx); err != nil {
				s.writeListingFailure(w, r, err)
				return
			}
		case teamOK:
			candidate = teamItem
			if teamItem, teamOK, err = team.next(ctx); err != nil {
				s.writeListingFailure(w, r, err)
				return
			}
		default:
			httpx.WriteJSON(w, http.StatusOK, bucketPage{Items: page, NextCursor: ""})
			return
		}
		last = candidate.Name
		allowed, ok := s.authorizeBucketRow(w, r, claims, candidate)
		if !ok {
			return
		}
		if allowed {
			page = append(page, candidate)
		}
	}
	// The page is full: the merged cursor continues after the last examined
	// candidate, and only when another candidate actually follows.
	next := ""
	if ownerOK || teamOK {
		next = httpx.EncodeCursor(last)
	}
	httpx.WriteJSON(w, http.StatusOK, bucketPage{Items: page, NextCursor: next})
}
