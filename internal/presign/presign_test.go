package presign

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T, maxTTL time.Duration) *Signer {
	t.Helper()
	signer, err := Load(t.TempDir(), maxTTL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return signer
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer := testSigner(t, time.Hour)
	now := time.Now()
	payload := Payload{
		Bucket:      "photos",
		Key:         "albums/2026/cover.jpg",
		Method:      "get",
		Subject:     "user_1",
		Kind:        "user",
		Team:        "team_1",
		PermVer:     42,
		ExpiresAt:   now.Add(5 * time.Minute),
		ContentType: "image/jpeg",
		MaxBytes:    1 << 20,
	}

	token, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verified, err := signer.Verify(token, "GET", payload.Bucket, payload.Key, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Bucket != payload.Bucket || verified.Key != payload.Key {
		t.Fatalf("verified object = %s/%s, want %s/%s", verified.Bucket, verified.Key, payload.Bucket, payload.Key)
	}
	if verified.Method != "GET" {
		t.Fatalf("verified method = %q, want GET", verified.Method)
	}
	if verified.Subject != payload.Subject || verified.Kind != payload.Kind || verified.Team != payload.Team || verified.PermVer != payload.PermVer {
		t.Fatalf("verified subject = %+v, want %+v", verified, payload)
	}
	if verified.ContentType != payload.ContentType || verified.MaxBytes != payload.MaxBytes {
		t.Fatalf("verified payload lost content type or max bytes: %+v", verified)
	}
	if got := verified.ExpiresAt.Unix(); got != payload.ExpiresAt.Unix() {
		t.Fatalf("verified expiry = %d, want %d", got, payload.ExpiresAt.Unix())
	}
}

func TestVerifyAcceptsHeadForGetToken(t *testing.T) {
	signer := testSigner(t, time.Hour)
	now := time.Now()
	token, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(token, "HEAD", "b", "k", now); err != nil {
		t.Fatalf("Verify HEAD with a GET token: %v", err)
	}
}

func TestVerifyRejectsWrongMethod(t *testing.T) {
	signer := testSigner(t, time.Hour)
	now := time.Now()
	putToken, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "PUT", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(putToken, "GET", "b", "k", now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Verify PUT token with GET = %v, want ErrMalformed", err)
	}
	getToken, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(getToken, "PUT", "b", "k", now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Verify GET token with PUT = %v, want ErrMalformed", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	signer := testSigner(t, time.Hour)
	now := time.Now()
	token, err := signer.Sign(Payload{Bucket: "b", Key: "a.txt", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	encodedPayload, encodedMAC, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("token %q has no separator", token)
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var wire wirePayload
	if err := json.Unmarshal(rawPayload, &wire); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	wire.Key = "b.txt"
	reEncoded, err := encodePayload(wire)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	if _, err := signer.Verify(reEncoded+"."+encodedMAC, "GET", "b", "b.txt", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered payload = %v, want ErrSignature", err)
	}

	mac, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	mac[0] ^= 0x01
	flipped := base64.RawURLEncoding.EncodeToString(mac)
	if _, err := signer.Verify(encodedPayload+"."+flipped, "GET", "b", "a.txt", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("flipped signature = %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	signer := testSigner(t, time.Hour)
	now := time.Now()
	token, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(10 * time.Second)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(token, "GET", "b", "k", now.Add(500*time.Millisecond)); err != nil {
		t.Fatalf("Verify inside the lifetime: %v", err)
	}
	if _, err := signer.Verify(token, "GET", "b", "k", now.Add(11*time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify after expiry = %v, want ErrExpired", err)
	}
}

func TestSignRejectsTTLAboveMaximum(t *testing.T) {
	signer := testSigner(t, time.Minute)
	now := signer.now()
	if _, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute + time.Second)}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized ttl = %v, want ErrMalformed", err)
	}
	if _, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(-time.Second)}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expiry in the past = %v, want ErrMalformed", err)
	}
}

func TestSignRejectsIncompletePayload(t *testing.T) {
	signer := testSigner(t, time.Minute)
	expiry := signer.now().Add(time.Minute)
	cases := map[string]Payload{
		"missing bucket":  {Key: "k", Method: "GET", Subject: "u1", ExpiresAt: expiry},
		"missing key":     {Bucket: "b", Method: "GET", Subject: "u1", ExpiresAt: expiry},
		"missing subject": {Bucket: "b", Key: "k", Method: "GET", ExpiresAt: expiry},
		"missing method":  {Bucket: "b", Key: "k", Subject: "u1", ExpiresAt: expiry},
		"missing expiry":  {Bucket: "b", Key: "k", Method: "GET", Subject: "u1"},
		"negative bytes":  {Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: expiry, MaxBytes: -1},
	}
	for name, payload := range cases {
		if _, err := signer.Sign(payload); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Sign = %v, want ErrMalformed", name, err)
		}
	}
}

func TestVerifyRejectsWrongObjectAndMalformedTokens(t *testing.T) {
	signer := testSigner(t, time.Minute)
	now := time.Now()
	token, err := signer.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(token, "GET", "other", "k", now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrong bucket = %v, want ErrMalformed", err)
	}
	if _, err := signer.Verify(token, "GET", "b", "other", now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrong key = %v, want ErrMalformed", err)
	}
	for _, malformed := range []string{"", "no-separator", ".", "payload.", ".signature", "!!!.???"} {
		if _, err := signer.Verify(malformed, "GET", "b", "k", now); !errors.Is(err, ErrMalformed) {
			t.Errorf("Verify(%q) = %v, want ErrMalformed", malformed, err)
		}
	}
}

func TestLoadCreatesAndReusesKeyFile(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir, time.Minute)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	keyPath := filepath.Join(dir, keyFileName)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if info.Size() != keySize {
		t.Fatalf("key size = %d, want %d", info.Size(), keySize)
	}

	second, err := Load(dir, time.Minute)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	now := time.Now()
	token, err := first.Sign(Payload{Bucket: "b", Key: "k", Method: "GET", Subject: "u1", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := second.Verify(token, "GET", "b", "k", now); err != nil {
		t.Fatalf("reloaded signer rejected a token from the first: %v", err)
	}
}

func TestLoadRefusesWrongKeySize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := Load(dir, time.Minute); err == nil {
		t.Fatal("Load accepted a key file with the wrong size")
	}
}

func TestLoadValidatesArguments(t *testing.T) {
	if _, err := Load("", time.Minute); err == nil {
		t.Fatal("Load accepted an empty key directory")
	}
	if _, err := Load(t.TempDir(), 0); err == nil {
		t.Fatal("Load accepted a non-positive maximum TTL")
	}
}
