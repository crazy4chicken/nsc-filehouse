// Package presign mints and verifies HMAC-SHA256 presigned URL tokens for
// nsc-filewarehouse.
//
// A token is base64url(payload JSON) + "." + base64url(HMAC-SHA256(key,
// base64url(payload JSON))). The MAC covers the exact encoded payload segment
// as it appears in the token, so re-encoding the payload after signing
// invalidates the token.
package presign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Errors reported by Sign and Verify.
var (
	// ErrExpired reports a token whose expiry has been reached.
	ErrExpired = errors.New("presign: token has expired")
	// ErrSignature reports a token whose MAC does not match its payload.
	ErrSignature = errors.New("presign: signature mismatch")
	// ErrMalformed reports a token that is not well formed, is missing a
	// required claim, or does not apply to the requested method, bucket, or
	// key.
	ErrMalformed = errors.New("presign: malformed token")
)

const (
	// keyFileName is the signing key inside the key directory.
	keyFileName = "presign-hmac.key"
	// keySize is the required signing key length in bytes.
	keySize = 32
	// maxEncodedPayloadBytes bounds decoded payloads before parsing.
	maxEncodedPayloadBytes = 16 << 10

	methodGET  = "GET"
	methodHEAD = "HEAD"
	methodPUT  = "PUT"
)

// allowedMethods is the set of HTTP methods a token can be minted for. HEAD is
// accepted because a GET token also authorizes a HEAD redemption.
var allowedMethods = map[string]struct{}{
	methodGET:  {},
	methodHEAD: {},
	methodPUT:  {},
}

// Payload is the signed content of a presigned URL token. Subject, Kind,
// Team, and PermVer are re-checked against teamusers at redemption time.
type Payload struct {
	Bucket      string
	Key         string
	Method      string
	Subject     string
	Kind        string
	Team        string
	PermVer     int64
	ExpiresAt   time.Time
	ContentType string
	MaxBytes    int64
}

// wirePayload is the JSON encoding of Payload. Expiry is stored as Unix
// seconds, which truncates sub-second precision downward (a token never lives
// longer than requested).
type wirePayload struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	Method      string `json:"method"`
	Subject     string `json:"subject"`
	Kind        string `json:"kind,omitempty"`
	Team        string `json:"team,omitempty"`
	PermVer     int64  `json:"perm_ver"`
	ExpiresAt   int64  `json:"exp"`
	ContentType string `json:"content_type,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
}

// Signer signs and verifies presigned URL tokens with a process-stable key.
type Signer struct {
	key    []byte
	maxTTL time.Duration
	now    func() time.Time
}

// Load opens the signing key in dir, creating <dir>/presign-hmac.key with 32
// random bytes and mode 0600 when it does not exist yet. An existing key must
// be exactly keySize bytes; anything else refuses startup instead of silently
// invalidating every outstanding presigned URL or weakening the signature.
//
// maxTTL is the longest lifetime Sign accepts; it must be positive.
func Load(dir string, maxTTL time.Duration) (*Signer, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("presign: key directory is required")
	}
	if maxTTL <= 0 {
		return nil, errors.New("presign: maximum TTL must be positive")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("presign: create key directory: %w", err)
	}
	key, err := loadOrCreateKey(filepath.Join(dir, keyFileName))
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, maxTTL: maxTTL, now: time.Now}, nil
}

// loadOrCreateKey creates the key file exclusively or reads the existing one.
func loadOrCreateKey(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return writeNewKey(file, path)
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("presign: open key file: %w", err)
	}

	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("presign: read key file: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("presign: key file %s holds %d bytes, want %d", path, len(key), keySize)
	}
	return key, nil
}

// writeNewKey fills a freshly created key file and removes it again when any
// step fails, so a partial key can never be reused by a later start.
func writeNewKey(file *os.File, path string) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("presign: generate key: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("presign: write key: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("presign: close key file: %w", err)
	}
	// The create mode is subject to the process umask, so tighten it again.
	if err := os.Chmod(path, 0o600); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("presign: restrict key file permissions: %w", err)
	}
	return key, nil
}

// Sign mints a token for p. The requested lifetime (ExpiresAt relative to now)
// must be positive and must not exceed the signer's maximum TTL; violations
// are reported as ErrMalformed.
func (s *Signer) Sign(p Payload) (string, error) {
	if s == nil || len(s.key) != keySize {
		return "", errors.New("presign: signer is not initialized")
	}
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if _, ok := allowedMethods[method]; !ok {
		return "", fmt.Errorf("%w: unsupported method %q", ErrMalformed, p.Method)
	}
	if strings.TrimSpace(p.Bucket) == "" {
		return "", fmt.Errorf("%w: bucket is required", ErrMalformed)
	}
	if p.Key == "" {
		return "", fmt.Errorf("%w: key is required", ErrMalformed)
	}
	if strings.TrimSpace(p.Subject) == "" {
		return "", fmt.Errorf("%w: subject is required", ErrMalformed)
	}
	if p.MaxBytes < 0 {
		return "", fmt.Errorf("%w: max bytes must not be negative", ErrMalformed)
	}
	if p.ExpiresAt.IsZero() {
		return "", fmt.Errorf("%w: expiry is required", ErrMalformed)
	}
	now := s.now()
	if !p.ExpiresAt.After(now) {
		return "", fmt.Errorf("%w: expiry must be in the future", ErrMalformed)
	}
	if s.maxTTL > 0 {
		if ttl := p.ExpiresAt.Sub(now); ttl > s.maxTTL {
			return "", fmt.Errorf("%w: ttl %s exceeds the maximum %s", ErrMalformed, ttl, s.maxTTL)
		}
	}

	encodedPayload, err := encodePayload(wirePayload{
		Bucket:      p.Bucket,
		Key:         p.Key,
		Method:      method,
		Subject:     p.Subject,
		Kind:        p.Kind,
		Team:        p.Team,
		PermVer:     p.PermVer,
		ExpiresAt:   p.ExpiresAt.Unix(),
		ContentType: p.ContentType,
		MaxBytes:    p.MaxBytes,
	})
	if err != nil {
		return "", err
	}
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(s.mac(encodedPayload)), nil
}

// Verify authenticates token and checks that it applies to the requested
// method, bucket, and key at time now.
//
// A token minted for GET also authorizes HEAD. Expired tokens report
// ErrExpired; tokens that do not apply to the request report ErrMalformed, so
// callers can distinguish "no longer valid" (410) from "wrong request" (403).
func (s *Signer) Verify(token, method, bucket, key string, now time.Time) (Payload, error) {
	if s == nil || len(s.key) != keySize {
		return Payload{}, errors.New("presign: signer is not initialized")
	}
	encodedPayload, encodedMAC, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok || encodedPayload == "" || encodedMAC == "" {
		return Payload{}, fmt.Errorf("%w: token must hold a payload and a signature", ErrMalformed)
	}

	providedMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || len(providedMAC) != sha256.Size {
		return Payload{}, fmt.Errorf("%w: invalid signature encoding", ErrMalformed)
	}
	if !hmac.Equal(providedMAC, s.mac(encodedPayload)) {
		return Payload{}, ErrSignature
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: invalid payload encoding", ErrMalformed)
	}
	if len(rawPayload) > maxEncodedPayloadBytes {
		return Payload{}, fmt.Errorf("%w: payload is too large", ErrMalformed)
	}
	var wire wirePayload
	if err := json.Unmarshal(rawPayload, &wire); err != nil {
		return Payload{}, fmt.Errorf("%w: invalid payload", ErrMalformed)
	}
	if wire.Bucket == "" || wire.Key == "" || wire.Subject == "" {
		return Payload{}, fmt.Errorf("%w: payload is incomplete", ErrMalformed)
	}
	if wire.ExpiresAt <= 0 {
		return Payload{}, fmt.Errorf("%w: payload has no expiry", ErrMalformed)
	}

	requestedMethod := strings.ToUpper(strings.TrimSpace(method))
	if _, ok := allowedMethods[requestedMethod]; !ok {
		return Payload{}, fmt.Errorf("%w: unsupported method %q", ErrMalformed, method)
	}
	if wire.Method != requestedMethod && !(wire.Method == methodGET && requestedMethod == methodHEAD) {
		return Payload{}, fmt.Errorf("%w: token is not valid for %s", ErrMalformed, requestedMethod)
	}
	if wire.Bucket != bucket || wire.Key != key {
		return Payload{}, fmt.Errorf("%w: token does not match the requested object", ErrMalformed)
	}
	if !now.Before(time.Unix(wire.ExpiresAt, 0)) {
		return Payload{}, ErrExpired
	}

	return Payload{
		Bucket:      wire.Bucket,
		Key:         wire.Key,
		Method:      wire.Method,
		Subject:     wire.Subject,
		Kind:        wire.Kind,
		Team:        wire.Team,
		PermVer:     wire.PermVer,
		ExpiresAt:   time.Unix(wire.ExpiresAt, 0),
		ContentType: wire.ContentType,
		MaxBytes:    wire.MaxBytes,
	}, nil
}

// mac computes the HMAC over the encoded payload segment.
func (s *Signer) mac(encodedPayload string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

// encodePayload marshals and base64url-encodes the payload.
func encodePayload(wire wirePayload) (string, error) {
	raw, err := json.Marshal(wire)
	if err != nil {
		return "", fmt.Errorf("presign: encode payload: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
