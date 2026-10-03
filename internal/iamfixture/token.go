package iamfixture

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Claims describes the access token the fixture mints. Zero fields are filled
// with fixture defaults: Issuer and Audience from the server, Subject with
// "test-user", Kind with "user", IssuedAt with the current time and ExpiresAt
// with IssuedAt plus the configured token TTL.
type Claims struct {
	Issuer    string
	Audience  string
	Subject   string
	Kind      string
	Team      string
	PermVer   int64
	AuthTime  int64
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// tokenHeader is the JOSE header of every fixture token.
type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// tokenPayload is the JWT claim set emitted by the fixture.
type tokenPayload struct {
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	Subject   string   `json:"sub"`
	Kind      string   `json:"kind"`
	Team      string   `json:"team,omitempty"`
	PermVer   int64    `json:"perm_ver"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	AuthTime  int64    `json:"auth_time"`
	AMR       []string `json:"amr,omitempty"`
}

// jwkSet is the JWKS document served at /.well-known/jwks.json.
type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey is one Ed25519 public key in JWK form.
type jwkKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
}

// Issue mints a compact EdDSA JWT. The signature is computed with
// crypto/ed25519 over base64url(header) + "." + base64url(payload), so the
// token verifies against the JWKS document the fixture serves.
func (s *Server) Issue(claims Claims) string {
	now := s.now()

	s.mu.Lock()
	ttl := s.tokenTTL
	expire := s.expireTokens
	s.mu.Unlock()

	if claims.Issuer == "" {
		claims.Issuer = s.issuer
	}
	if claims.Audience == "" {
		claims.Audience = s.audience
	}
	if claims.Subject == "" {
		claims.Subject = "test-user"
	}
	if claims.Kind == "" {
		claims.Kind = "user"
	}
	issuedAt := claims.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = now
	}
	expiresAt := claims.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = issuedAt.Add(ttl)
	}
	if expire {
		expiresAt = now.Add(-time.Minute)
	}

	header, err := json.Marshal(tokenHeader{Algorithm: "EdDSA", KeyID: s.kid, Type: "JWT"})
	if err != nil {
		return ""
	}
	payload, err := json.Marshal(tokenPayload{
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Subject:   claims.Subject,
		Kind:      claims.Kind,
		Team:      claims.Team,
		PermVer:   claims.PermVer,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
		AuthTime:  claims.AuthTime,
		AMR:       claims.AMR,
	})
	if err != nil {
		return ""
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.private, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// publicJWK renders the fixture verification key. The JWKS document and any
// test that inspects the key share this representation.
func (s *Server) publicJWK() jwkKey {
	return jwkKey{
		KeyType:   "OKP",
		Curve:     "Ed25519",
		X:         base64.RawURLEncoding.EncodeToString(s.public),
		KeyID:     s.kid,
		Algorithm: "EdDSA",
		Use:       "sig",
	}
}

// SetTokenTTL changes the lifetime used by tokens minted after the call. A
// non-positive value is ignored.
func (s *Server) SetTokenTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	s.tokenTTL = ttl
	s.mu.Unlock()
}

// ExpireTokens forces every subsequently issued token to carry an expiration
// one minute in the past, which lets tests exercise the expired-token path
// deterministically. Call ResetTokenExpiration to mint valid tokens again.
func (s *Server) ExpireTokens() {
	s.mu.Lock()
	s.expireTokens = true
	s.mu.Unlock()
}

// ResetTokenExpiration undoes ExpireTokens.
func (s *Server) ResetTokenExpiration() {
	s.mu.Lock()
	s.expireTokens = false
	s.mu.Unlock()
}
