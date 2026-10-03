package iamauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrServiceAuth reports that the service credential exchange with teamusers
// failed: the client-credentials endpoint answered with a non-2xx status or
// with a payload that cannot be used. Callers can test it with errors.Is.
//
// The error chain never carries the client secret or the issued access token.
var ErrServiceAuth = errors.New("iam: service authentication failed")

const (
	// defaultServiceTokenTimeout bounds one client-credentials exchange when
	// no timeout is configured.
	defaultServiceTokenTimeout = 15 * time.Second
	// maxTokenResponseBytes bounds the client-credentials response we decode.
	maxTokenResponseBytes = 64 << 10
	// maxErrorBodyBytes bounds how much of an error response is inspected.
	maxErrorBodyBytes = 4 << 10
	// maxErrorDetailChars bounds the length of a reported response detail.
	maxErrorDetailChars = 200
	// maxTokenLifetimeSeconds rejects absurd expires_in values.
	maxTokenLifetimeSeconds = 24 * 60 * 60
)

// serviceTokenError is the typed failure of a client-credentials exchange. It
// unwraps to ErrServiceAuth and deliberately contains no credential material.
type serviceTokenError struct {
	status int
	detail string
}

func (e *serviceTokenError) Error() string {
	detail := e.detail
	if detail == "" {
		detail = "no response detail"
	}
	if e.status == 0 {
		return "iam: client credentials exchange failed: " + detail
	}
	return fmt.Sprintf("iam: client credentials exchange failed: HTTP %d: %s", e.status, detail)
}

// Unwrap lets callers match the exchange failure with errors.Is(err, ErrServiceAuth).
func (e *serviceTokenError) Unwrap() error { return ErrServiceAuth }

// staticTokenSource returns a fixed service token configured by the operator.
type staticTokenSource struct {
	token string
}

// Token implements the callback shape expected by iam.WithTokenSource.
func (s staticTokenSource) Token() (string, error) {
	token := strings.TrimSpace(s.token)
	if token == "" {
		return "", errors.New("iam: static service token is empty")
	}
	return token, nil
}

// clientCredentialsSource exchanges a client id/secret pair for short-lived
// service access tokens through POST /auth/client-credentials.
//
// A fetched token is cached until 80% of its advertised expires_in has
// elapsed; concurrent callers share a single in-flight refresh so a cold cache
// under load issues one request.
type clientCredentialsSource struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	timeout      time.Duration
	now          func() time.Time

	mu       sync.Mutex
	cached   *cachedServiceToken
	inflight *tokenRefresh
}

type cachedServiceToken struct {
	value     string
	expiresAt time.Time
}

type tokenRefresh struct {
	done  chan struct{}
	token string
	err   error
}

// newClientCredentialsSource builds the credential source. hc defaults to
// http.DefaultClient and timeout defaults to defaultServiceTokenTimeout.
func newClientCredentialsSource(baseURL, clientID, clientSecret string, hc *http.Client, timeout time.Duration) *clientCredentialsSource {
	if hc == nil {
		hc = http.DefaultClient
	}
	if timeout <= 0 {
		timeout = defaultServiceTokenTimeout
	}
	return &clientCredentialsSource{
		baseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		httpClient:   hc,
		timeout:      timeout,
		now:          time.Now,
	}
}

// Token implements the callback shape expected by iam.WithTokenSource.
func (s *clientCredentialsSource) Token() (string, error) {
	now := s.now()

	s.mu.Lock()
	if s.cached != nil && now.Before(s.cached.expiresAt) {
		token := s.cached.value
		s.mu.Unlock()
		return token, nil
	}
	if call := s.inflight; call != nil {
		s.mu.Unlock()
		<-call.done
		return call.token, call.err
	}
	call := &tokenRefresh{done: make(chan struct{})}
	s.inflight = call
	s.mu.Unlock()

	token, ttl, err := s.exchange()

	s.mu.Lock()
	if s.inflight == call {
		s.inflight = nil
	}
	if err == nil {
		s.cached = &cachedServiceToken{value: token, expiresAt: s.now().Add(ttl)}
	}
	call.token, call.err = token, err
	close(call.done)
	s.mu.Unlock()

	return token, err
}

// exchange performs one client-credentials request and returns the access
// token together with the lifetime it should be cached for.
func (s *clientCredentialsSource) exchange() (string, time.Duration, error) {
	if s.baseURL == "" {
		return "", 0, errors.New("iam: base URL is required for client credentials")
	}
	if s.clientID == "" || s.clientSecret == "" {
		return "", 0, errors.New("iam: client id and client secret are both required")
	}

	requestBody, err := json.Marshal(struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}{ClientID: s.clientID, ClientSecret: s.clientSecret})
	if err != nil {
		return "", 0, fmt.Errorf("iam: encode client credentials request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/auth/client-credentials", bytes.NewReader(requestBody))
	if err != nil {
		return "", 0, fmt.Errorf("iam: create client credentials request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("iam: client credentials request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", 0, &serviceTokenError{status: response.StatusCode, detail: responseDetail(response.Body)}
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxTokenResponseBytes)).Decode(&payload); err != nil {
		return "", 0, &serviceTokenError{status: response.StatusCode, detail: "malformed response body"}
	}
	token := strings.TrimSpace(payload.AccessToken)
	if token == "" {
		return "", 0, &serviceTokenError{status: response.StatusCode, detail: "response is missing access_token"}
	}
	if payload.ExpiresIn <= 0 || payload.ExpiresIn > maxTokenLifetimeSeconds {
		return "", 0, &serviceTokenError{status: response.StatusCode, detail: "response has an invalid expires_in"}
	}

	lifetime := time.Duration(payload.ExpiresIn) * time.Second
	// Integer math keeps the 80% window exact and allocation free.
	ttl := lifetime * 8 / 10
	return token, ttl, nil
}

// responseDetail extracts a short, single-line description from an error
// response body. It reads at most maxErrorBodyBytes and never includes request
// credentials.
func responseDetail(body io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes))
	if err != nil || len(raw) == 0 {
		return "no response detail"
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(raw, &problem) == nil {
		if detail := strings.TrimSpace(problem.Detail); detail != "" {
			return truncateDetail(detail)
		}
	}
	return truncateDetail(string(raw))
}

// truncateDetail collapses whitespace and caps the detail length so a remote
// body cannot flood logs or problem documents.
func truncateDetail(detail string) string {
	detail = strings.Join(strings.Fields(detail), " ")
	if detail == "" {
		return "no response detail"
	}
	if len(detail) > maxErrorDetailChars {
		return detail[:maxErrorDetailChars]
	}
	return detail
}
