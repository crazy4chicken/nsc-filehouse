package httpapi

import (
	"net/http"
	"sort"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// subjectRef identifies a subject on the wire.
type subjectRef struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type usageResponse struct {
	Subject      subjectRef       `json:"subject"`
	UsedBytes    int64            `json:"used_bytes"`
	UsedObjects  int64            `json:"used_objects"`
	QuotaBytes   int64            `json:"quota_bytes"`
	QuotaObjects int64            `json:"quota_objects"`
	Buckets      []store.UsageRow `json:"buckets"`
}

type permissionsResponse struct {
	Subject     subjectRef `json:"subject"`
	Permissions []string   `json:"permissions"`
}

// handleUsage reports the caller's own aggregate usage, per bucket breakdown
// and subject quota. The subject always comes from the verified token, so a
// caller can never read another subject's usage.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	// The self service quota subject is the subject's user id: the store matches
	// every kind except "team" against the bucket owner, which is exactly the
	// caller's own projection. Kind "user" also keys the quota the admin plane
	// manages for the caller.
	rows, err := s.Store().Usage(r.Context(), "user", claims.Subject)
	if err != nil {
		s.log.Error("load usage failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	quota, found, err := s.Store().GetQuota(r.Context(), "user", claims.Subject)
	if err != nil {
		s.log.Error("load quota failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	var usedBytes, usedObjects int64
	for _, row := range rows {
		usedBytes += row.UsedBytes
		usedObjects += row.UsedObjects
	}
	response := usageResponse{
		Subject:     subjectRef{ID: claims.Subject, Kind: subjectKind(claims)},
		UsedBytes:   usedBytes,
		UsedObjects: usedObjects,
		Buckets:     rows,
	}
	if found {
		response.QuotaBytes = quota.MaxBytes
		response.QuotaObjects = quota.MaxObjects
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

// handlePermissions lists the caller's effective grants. Deny keys keep their
// "!" prefix so a revoked permission stays visible as a deny.
func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	grants, err := s.Authorizer().Grants(r.Context(), claims)
	if err != nil {
		s.log.Error("load permission grants failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return
	}
	keys := make([]string, 0, len(grants))
	for _, grant := range grants {
		keys = append(keys, grantKey(grant))
	}
	sort.Strings(keys)
	httpx.WriteJSON(w, http.StatusOK, permissionsResponse{
		Subject:     subjectRef{ID: claims.Subject, Kind: subjectKind(claims)},
		Permissions: keys,
	})
}

// grantKey renders one grant in canonical "[!]resource:action:scope" form.
func grantKey(grant iam.Permission) string {
	prefix := ""
	if grant.Deny {
		prefix = "!"
	}
	return prefix + grant.Resource + ":" + grant.Action + ":" + grant.Scope
}
