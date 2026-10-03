package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/crazy4chicken/nsc-filewarehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filewarehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filewarehouse/internal/store"
)

const (
	// verbManage is the permission action of the admin plane.
	verbManage = "manage"

	// quotaKindUser and quotaKindTeam are the quota subject kinds the admin
	// plane accepts; the store keeps the value verbatim.
	quotaKindUser = "user"
	quotaKindTeam = "team"

	// maxQuotaSubjectIDBytes bounds the subject id accepted by the quota
	// upsert; real subject ids are short opaque identifiers.
	maxQuotaSubjectIDBytes = 256

	// physicalBlobLimit bounds the filesystem walk behind the stats endpoint so
	// a huge or damaged blob directory cannot stall an admin request forever.
	physicalBlobLimit = 1_000_000
)

// validQuotaKind reports whether kind names a supported quota subject kind.
func validQuotaKind(kind string) bool {
	return kind == quotaKindUser || kind == quotaKindTeam
}

// adminStatsResponse adds the on-disk blob inventory to the store totals so an
// operator can spot rows without files and files without rows.
type adminStatsResponse struct {
	store.Stats
	PhysicalBlobs int64 `json:"physical_blobs"`
	PhysicalBytes int64 `json:"physical_bytes"`
}

// handleAdminStats reports platform-wide totals plus the physical blob
// inventory. It requires a manage:any grant.
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	if !s.decideAny(w, r, claims, verbManage) {
		return
	}
	if s.Store() == nil || s.Blobs() == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	stats, err := s.Store().Stats(r.Context())
	if err != nil {
		s.Logger().Error("admin stats: store totals failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	physicalBlobs, physicalBytes, err := countPhysicalBlobs(r.Context(), s.Blobs())
	if err != nil {
		s.Logger().Error("admin stats: blob inventory failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, adminStatsResponse{
		Stats:         stats,
		PhysicalBlobs: physicalBlobs,
		PhysicalBytes: physicalBytes,
	})
}

// countPhysicalBlobs reports how many blob files exist on disk and how large
// they are. The walk is bounded so a huge blob directory cannot stall an admin
// request; files that disappear mid-walk (a concurrent GC pass) are skipped.
func countPhysicalBlobs(ctx context.Context, blobs *blob.Store) (int64, int64, error) {
	var count, total int64
	err := blobs.ListHashes(ctx, physicalBlobLimit, func(hash string) error {
		size, err := blobs.Stat(hash)
		if err != nil {
			if errors.Is(err, blob.ErrNotFound) {
				return nil
			}
			return err
		}
		count++
		total += size
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return count, total, nil
}

// quotaListResponse is the paged quota listing; next_cursor is empty on the
// last page.
type quotaListResponse struct {
	Items      []store.Quota `json:"items"`
	NextCursor string        `json:"next_cursor"`
}

// handleAdminListQuotas lists subject quotas. An absent or empty ?kind= lists
// both kinds ordered by (subject_kind, subject_id); a non-empty value must be
// user or team. Cursors are the store's opaque tokens and are passed through
// verbatim.
func (s *Server) handleAdminListQuotas(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	if !s.decideAny(w, r, claims, verbManage) {
		return
	}
	if s.Store() == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind != "" && !validQuotaKind(kind) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	limit, ok := parsePageLimit(w, r)
	if !ok {
		return
	}
	items, next, err := s.Store().ListQuotas(r.Context(), kind, r.URL.Query().Get("cursor"), effectiveLimit(limit))
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
		s.Logger().Error("admin quota listing failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	if items == nil {
		items = []store.Quota{}
	}
	httpx.WriteJSON(w, http.StatusOK, quotaListResponse{Items: items, NextCursor: next})
}

// adminQuotaRequest is the JSON body of PUT /api/v1/admin/quotas/{kind}/{id}.
// Zero means unlimited in either dimension.
type adminQuotaRequest struct {
	MaxBytes   int64 `json:"max_bytes"`
	MaxObjects int64 `json:"max_objects"`
}

// handleAdminPutQuota upserts one subject quota and returns the stored row.
func (s *Server) handleAdminPutQuota(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	if !s.decideAny(w, r, claims, verbManage) {
		return
	}
	if s.Store() == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	kind, ok := decodedPathParam(r, "kind")
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	id, ok := decodedPathParam(r, "id")
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	kind = strings.TrimSpace(kind)
	id = strings.TrimSpace(id)
	if !validQuotaKind(kind) || id == "" || len(id) > maxQuotaSubjectIDBytes {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	var req adminQuotaRequest
	if !decodeRequestBody(w, r, &req) {
		return
	}
	if req.MaxBytes < 0 || req.MaxObjects < 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	quota := store.Quota{
		SubjectKind: kind,
		SubjectID:   id,
		MaxBytes:    req.MaxBytes,
		MaxObjects:  req.MaxObjects,
	}
	if err := s.Store().PutQuota(r.Context(), quota); err != nil {
		s.Logger().Error("admin quota upsert failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	stored, found, err := s.Store().GetQuota(r.Context(), kind, id)
	if err != nil || !found {
		// The row was just written; not finding it again is an internal
		// inconsistency rather than a caller error.
		s.Logger().Error("admin quota read-back failed", "found", found, "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, stored)
}

// handleAdminGC runs one garbage collection pass and returns its report.
//
// A pass that finishes with per-step errors still completes every reachable
// step, so it is answered 200 with a non-zero errors counter instead of a 5xx.
func (s *Server) handleAdminGC(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	if !s.decideAny(w, r, claims, verbManage) {
		return
	}
	reaper := s.Reaper()
	if reaper == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	report, err := reaper.Once(r.Context())
	if err != nil {
		s.Logger().Warn("manual gc pass completed with errors", "error", err)
	}
	httpx.WriteJSON(w, http.StatusOK, report)
}
