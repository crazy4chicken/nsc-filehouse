package iamauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
)

// allowCall records one cascade step.
type allowCall struct {
	Claims     iam.Claims
	Permission string
	Resource   iam.Resource
}

// verdict is one scripted authorization answer.
type verdict struct {
	allow  bool
	reason string
}

// scriptedAllow returns an allowFunc that answers from verdicts and records
// every call. Unknown keys answer "no matching grant", like the SDK.
func scriptedAllow(verdicts map[string]verdict, calls *[]allowCall) allowFunc {
	return func(_ context.Context, claims iam.Claims, permission string, resource iam.Resource) (bool, string) {
		*calls = append(*calls, allowCall{Claims: claims, Permission: permission, Resource: resource})
		answer, ok := verdicts[permission]
		if !ok {
			return false, "no matching grant"
		}
		return answer.allow, answer.reason
	}
}

func cascadeAuthorizer(verdicts map[string]verdict, calls *[]allowCall) *Authorizer {
	return &Authorizer{allow: scriptedAllow(verdicts, calls)}
}

func testClaims(subject string) iam.Claims {
	return iam.Claims{Subject: subject, Kind: "user", PermVer: 7}
}

func permissionsOf(calls []allowCall) []string {
	keys := make([]string, 0, len(calls))
	for _, call := range calls {
		keys = append(keys, call.Permission)
	}
	return keys
}

func TestDecideAnyScopeAllowWins(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{
		"filehouse:read:any": {allow: true, reason: "permission granted"},
	}, &calls)

	allowed, reason, err := authorizer.Decide(context.Background(), testClaims("u1"), "read", iam.Resource{OwnerID: "u1", TeamID: "t1"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !allowed {
		t.Fatalf("Decide denied: %s", reason)
	}
	if got := permissionsOf(calls); len(got) != 1 || got[0] != "filehouse:read:any" {
		t.Fatalf("cascade attempted %v, want only the any scope", got)
	}
}

func TestDecideExplicitDenyIsTerminal(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{
		"filehouse:write:any":  {allow: false, reason: policyDeniedReason},
		"filehouse:write:team": {allow: true, reason: "permission granted"},
		"filehouse:write:own":  {allow: true, reason: "permission granted"},
	}, &calls)

	allowed, reason, err := authorizer.Decide(context.Background(), testClaims("u1"), "write", iam.Resource{OwnerID: "u1", TeamID: "t1"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if allowed {
		t.Fatal("Decide allowed a request with an explicit deny")
	}
	if !strings.Contains(reason, "filehouse:write:any") {
		t.Fatalf("reason %q does not name the denying key", reason)
	}
	if got := permissionsOf(calls); len(got) != 1 {
		t.Fatalf("cascade continued past an explicit deny: %v", got)
	}
}

func TestDecideSkipsTeamScopeWithoutTeam(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{}, &calls)

	allowed, _, err := authorizer.Decide(context.Background(), testClaims("u1"), "read", iam.Resource{OwnerID: "u1"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if allowed {
		t.Fatal("Decide allowed a request without grants")
	}
	want := []string{"filehouse:read:any", "filehouse:read:own"}
	if got := permissionsOf(calls); !equalStrings(got, want) {
		t.Fatalf("cascade attempted %v, want %v", got, want)
	}
}

func TestDecideSkipsOwnScopeForNonOwner(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{}, &calls)

	allowed, reason, err := authorizer.Decide(context.Background(), testClaims("u1"), "read", iam.Resource{OwnerID: "u2", TeamID: "t1"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if allowed {
		t.Fatal("Decide allowed a request without grants")
	}
	want := []string{"filehouse:read:any", "filehouse:read:team"}
	if got := permissionsOf(calls); !equalStrings(got, want) {
		t.Fatalf("cascade attempted %v, want %v", got, want)
	}
	if strings.Contains(reason, ":own") {
		t.Fatalf("reason %q names a scope that was never attempted", reason)
	}
}

func TestDecideDeniesWhenAllScopesAreExhausted(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{}, &calls)

	allowed, reason, err := authorizer.Decide(context.Background(), testClaims("u1"), "delete", iam.Resource{OwnerID: "u1", TeamID: "t1"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if allowed {
		t.Fatal("Decide allowed a request without grants")
	}
	want := []string{"filehouse:delete:any", "filehouse:delete:team", "filehouse:delete:own"}
	if got := permissionsOf(calls); !equalStrings(got, want) {
		t.Fatalf("cascade attempted %v, want %v", got, want)
	}
	for _, key := range want {
		if !strings.Contains(reason, key) {
			t.Fatalf("reason %q does not list attempted key %s", reason, key)
		}
	}
}

func TestDecideRejectsUnsupportedVerb(t *testing.T) {
	var calls []allowCall
	authorizer := cascadeAuthorizer(map[string]verdict{}, &calls)

	allowed, _, err := authorizer.Decide(context.Background(), testClaims("u1"), "purge", iam.Resource{})
	if err == nil {
		t.Fatal("Decide accepted an unsupported verb")
	}
	if allowed {
		t.Fatal("Decide allowed an unsupported verb")
	}
	if len(calls) != 0 {
		t.Fatalf("unsupported verb reached the SDK: %v", permissionsOf(calls))
	}
}

// permissionsFixture serves the teamusers permission-cache endpoint.
type permissionsFixture struct {
	server   *httptest.Server
	requests *atomic.Int64
}

func newPermissionsFixture(t *testing.T, permVer int64, keys ...string) *permissionsFixture {
	t.Helper()
	grants := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		grants = append(grants, map[string]string{"key": key})
	}
	body, err := json.Marshal(map[string]any{"version": 2, "user_id": "u1", "perm_ver": permVer, "grants": grants})
	if err != nil {
		t.Fatalf("marshal fixture response: %v", err)
	}
	requests := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/authz/permissions/") {
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return &permissionsFixture{server: server, requests: requests}
}

func (f *permissionsFixture) authorizer(allow allowFunc) *Authorizer {
	return &Authorizer{
		permissions: iam.NewPermissionsClient(f.server.URL, iam.WithServiceToken("test-token")),
		allow:       allow,
	}
}

func TestDecideSubjectDeniesStalePermissionVersion(t *testing.T) {
	fixture := newPermissionsFixture(t, 9, "filehouse:read:any")
	authorizer := fixture.authorizer(func(context.Context, iam.Claims, string, iam.Resource) (bool, string) {
		t.Fatal("cascade must not run when the permission version is stale")
		return false, ""
	})

	allowed, reason, err := authorizer.DecideSubject(context.Background(), "u1", "user", "team_1", 3, "read", iam.Resource{OwnerID: "u2", TeamID: "team_1"})
	if err != nil {
		t.Fatalf("DecideSubject: %v", err)
	}
	if allowed {
		t.Fatal("DecideSubject allowed a presigned request with a stale permission version")
	}
	if reason != "permissions changed" {
		t.Fatalf("reason = %q, want %q", reason, "permissions changed")
	}
	if fixture.requests.Load() == 0 {
		t.Fatal("DecideSubject did not consult the permission endpoint")
	}
}

func TestDecideSubjectRunsCascadeWithEmbeddedSubject(t *testing.T) {
	fixture := newPermissionsFixture(t, 7, "filehouse:share:any")
	var calls []allowCall
	authorizer := fixture.authorizer(scriptedAllow(map[string]verdict{
		"filehouse:share:any": {allow: true, reason: "permission granted"},
	}, &calls))

	resource := iam.Resource{OwnerID: "u1", TeamID: "team_1"}
	allowed, reason, err := authorizer.DecideSubject(context.Background(), "u1", "user", "team_1", 7, "share", resource)
	if err != nil {
		t.Fatalf("DecideSubject: %v", err)
	}
	if !allowed {
		t.Fatalf("DecideSubject denied: %s", reason)
	}
	if len(calls) != 1 {
		t.Fatalf("cascade calls = %d, want 1", len(calls))
	}
	claims := calls[0].Claims
	if claims.Subject != "u1" || claims.Kind != "user" || claims.Team != "team_1" || claims.PermVer != 7 {
		t.Fatalf("cascade claims = %+v, want the embedded subject", claims)
	}
	if calls[0].Resource.OwnerID != resource.OwnerID || calls[0].Resource.TeamID != resource.TeamID {
		t.Fatalf("cascade resource = %+v, want %+v", calls[0].Resource, resource)
	}
}

func TestGrantsIncludeDenyKeys(t *testing.T) {
	fixture := newPermissionsFixture(t, 7, "filehouse:read:any", "!filehouse:delete:any")
	authorizer := fixture.authorizer(nil)

	grants, err := authorizer.Grants(context.Background(), testClaims("u1"))
	if err != nil {
		t.Fatalf("Grants: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want two entries", grants)
	}
	if grants[0].Deny || grants[0].Resource != resourceSegment || grants[0].Action != "read" || grants[0].Scope != "any" {
		t.Fatalf("grant[0] = %+v", grants[0])
	}
	if !grants[1].Deny || grants[1].Action != "delete" || grants[1].Scope != "any" {
		t.Fatalf("grant[1] = %+v, want a delete deny", grants[1])
	}
}

func TestNewAuthorizerValidatesBaseURL(t *testing.T) {
	if _, err := NewAuthorizer(Options{}); err == nil {
		t.Fatal("NewAuthorizer accepted an empty base URL")
	}
	if _, err := NewAuthorizer(Options{BaseURL: "not-a-url"}); err == nil {
		t.Fatal("NewAuthorizer accepted a URL without a scheme and host")
	}
	// Construction is offline: the SDK verifier is lazy and permutations of the
	// service credential must not require a reachable issuer.
	authorizer, err := NewAuthorizer(Options{BaseURL: "https://iam.example.invalid", ServiceToken: "static-token"})
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	authorizer.Close()
}

func TestAuthenticateWritesTeamusersProblemDocument(t *testing.T) {
	var reached bool
	// A zero Authorizer has no verifier, so every request fails closed. That
	// covers the missing-bearer and unverifiable-token paths without a JWKS
	// fixture.
	handler := (&Authorizer{}).Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	withRequestID := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), "req_01H")))
	})

	cases := []struct {
		name          string
		authorization string
		detail        string
	}{
		{"missing header", "", DetailTokenMissing},
		{"wrong scheme", "Basic dXNlcjpwYXNz", DetailTokenMalformed},
		{"empty token", "Bearer", DetailTokenMalformed},
		{"opaque token", "Bearer not.a.jwt", DetailInvalidToken},
	}
	for _, testCase := range cases {
		name, authorization, wantDetail := testCase.name, testCase.authorization, testCase.detail
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/buckets", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		// An attacker-controlled inbound request id must never surface.
		request.Header.Set("X-Request-Id", "attacker-supplied")
		withRequestID.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, recorder.Code)
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType != "application/problem+json" {
			t.Fatalf("%s: content type = %q", name, contentType)
		}
		var problem httpx.Problem
		if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
			t.Fatalf("%s: decode problem document: %v", name, err)
		}
		if problem.Type != "about:blank" || problem.Title != "Unauthorized" || problem.Status != http.StatusUnauthorized || problem.Detail != wantDetail {
			t.Fatalf("%s: problem document = %+v, want detail %q", name, problem, wantDetail)
		}
		if problem.Instance != "req_01H" {
			t.Fatalf("%s: instance = %q, want the request id from the context", name, problem.Instance)
		}
	}
	if reached {
		t.Fatal("an unauthenticated request reached the next handler")
	}
}

// TestDetailForVerificationError pins the mapping from SDK verifier messages to
// the stable 401 detail codes. The SDK reports free-form text, so an unhandled
// rewording must fall back to the generic code instead of misclassifying.
func TestDetailForVerificationError(t *testing.T) {
	cases := []struct {
		message string
		want    string
	}{
		{"verify access token: failed to parse jws: failed to parse JOSE headers: invalid character", DetailTokenMalformed},
		{"access token is empty", DetailTokenMalformed},
		{"verify access token: could not verify message using any of the signatures or keys", DetailTokenSignature},
		{"access token is expired", DetailTokenExpired},
		{"verify access token: \"exp\" not satisfied: token is expired", DetailTokenExpired},
		{"invalid access token issuer", DetailTokenIssuer},
		{"verify access token: \"iss\" not satisfied: values do not match", DetailTokenIssuer},
		{"invalid access token audience", DetailTokenAudience},
		{"verify access token: \"aud\" not satisfied: values do not match", DetailTokenAudience},
		{"verify access token: \"nbf\" not satisfied: token is not yet valid", DetailTokenClaims},
		{"invalid access token perm_ver", DetailTokenClaims},
		{"invalid access token step_up_time", DetailTokenClaims},
		{"access token subject is missing", DetailTokenClaims},
		{"fetch JWKS: dial tcp 127.0.0.1:18080: connect: connection refused", DetailTokenJWKS},
		{"fetch JWKS: x509: certificate signed by unknown authority", DetailTokenJWKS},
		{"JWKS cache is unavailable", DetailTokenJWKS},
		{"refresh JWKS for key \"k1\": boom", DetailTokenJWKS},
		{"something nobody classified yet", DetailInvalidToken},
		{"", DetailInvalidToken},
	}
	for _, testCase := range cases {
		if got := DetailForVerificationError(errors.New(testCase.message)); got != testCase.want {
			t.Errorf("DetailForVerificationError(%q) = %q, want %q", testCase.message, got, testCase.want)
		}
	}
	if got := DetailForVerificationError(nil); got != DetailInvalidToken {
		t.Errorf("DetailForVerificationError(nil) = %q, want %q", got, DetailInvalidToken)
	}
}

func TestAuthenticateFallsBackToResponseRequestID(t *testing.T) {
	handler := (&Authorizer{}).Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// A request-id middleware that only publishes the identifier as a response
	// header still yields a populated instance field.
	publishHeader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(httpx.HeaderRequestID, "req_header")
		handler.ServeHTTP(w, r)
	})
	recorder := httptest.NewRecorder()
	publishHeader.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/buckets", nil))

	var problem httpx.Problem
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem document: %v", err)
	}
	if problem.Instance != "req_header" {
		t.Fatalf("instance = %q, want the response header request id", problem.Instance)
	}
}

func TestAuthenticateOmitsUnknownRequestID(t *testing.T) {
	handler := (&Authorizer{}).Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/buckets", nil)
	request.Header.Set("Authorization", "Bearer not.a.jwt")
	request.Header.Set("X-Request-Id", "attacker-supplied")
	handler.ServeHTTP(recorder, request)
	if strings.Contains(recorder.Body.String(), "attacker") || strings.Contains(recorder.Body.String(), "instance") {
		t.Fatalf("problem document leaked a client-controlled instance: %s", recorder.Body.String())
	}
}

func TestHealthyChecksJWKS(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "keys present", status: http.StatusOK, body: `{"keys":[{"kty":"OKP","kid":"01J8Z3"}]}`},
		{name: "no keys", status: http.StatusOK, body: `{"keys":[]}`, wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, body: `{"detail":"jwks unavailable"}`, wantErr: true},
		{name: "invalid json", status: http.StatusOK, body: `not-json`, wantErr: true},
	}
	for _, testCase := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/jwks.json" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(testCase.status)
			_, _ = io.WriteString(w, testCase.body)
		}))
		authorizer := &Authorizer{baseURL: server.URL, httpClient: server.Client()}
		err := authorizer.Healthy(context.Background())
		if testCase.wantErr && err == nil {
			t.Errorf("%s: Healthy = nil, want an error", testCase.name)
		}
		if !testCase.wantErr && err != nil {
			t.Errorf("%s: Healthy = %v", testCase.name, err)
		}
		server.Close()
	}
}

func TestServiceTokenSourcePrefersStaticToken(t *testing.T) {
	options := Options{BaseURL: "https://iam.example.invalid", ServiceToken: "static-token", ClientID: "svc", ClientSecret: "secret"}
	source := serviceTokenSource(options, nil)
	if source == nil {
		t.Fatal("serviceTokenSource returned nil for a configured static token")
	}
	token, err := source()
	if err != nil {
		t.Fatalf("static token source: %v", err)
	}
	if token != "static-token" {
		t.Fatalf("token = %q, want the static token", token)
	}
	warnings := options.Warnings()
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "static") {
		t.Fatalf("Warnings() = %v, want a static-token precedence warning", warnings)
	}
}

func TestClientCredentialsSourceCachesUntilRefreshWindow(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/client-credentials" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("client-credentials request sent an Authorization header: %q", authorization)
		}
		count := requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":100,"token_type":"Bearer"}`, count)
	}))
	defer server.Close()

	source := newClientCredentialsSource(server.URL, "svc", "secret", server.Client(), 5*time.Second)
	current := time.Unix(1_700_000_000, 0)
	source.now = func() time.Time { return current }

	first, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if first != "tok-1" || second != "tok-1" {
		t.Fatalf("tokens = %q, %q, want the cached token twice", first, second)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 while the token is inside its window", got)
	}

	current = current.Add(81 * time.Second)
	third, err := source.Token()
	if err != nil {
		t.Fatalf("Token after the refresh window: %v", err)
	}
	if third != "tok-2" {
		t.Fatalf("token after refresh = %q, want tok-2", third)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 after the refresh window", got)
	}
}

func TestClientCredentialsSourceSharesConcurrentRefresh(t *testing.T) {
	var requests atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":100}`)
	}))
	defer server.Close()

	source := newClientCredentialsSource(server.URL, "svc", "secret", server.Client(), 5*time.Second)
	const callers = 8
	tokens := make([]string, callers)
	errs := make([]error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			tokens[index], errs[index] = source.Token()
		}(index)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wait.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", index, err)
		}
		if tokens[index] != "tok" {
			t.Fatalf("caller %d token = %q, want tok", index, tokens[index])
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want exactly one refresh for %d concurrent callers", got, callers)
	}
}

func TestClientCredentialsSourceReportsRejectedCredentials(t *testing.T) {
	const secret = "super-secret-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"type":"about:blank","title":"Unauthorized","status":401,"detail":"authentication failed"}`)
	}))
	defer server.Close()

	source := newClientCredentialsSource(server.URL, "svc", secret, server.Client(), time.Second)
	_, err := source.Token()
	if !errors.Is(err, ErrServiceAuth) {
		t.Fatalf("Token error = %v, want ErrServiceAuth", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the client secret: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error %q does not describe the rejection", err)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
