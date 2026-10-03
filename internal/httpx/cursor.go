package httpx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidCursor reports a cursor that is not a well formed opaque token.
var ErrInvalidCursor = errors.New("invalid cursor")

const cursorVersion = 1

type cursorEnvelope struct {
	Version int    `json:"v"`
	Value   string `json:"c"`
}

// EncodeCursor renders an opaque, URL safe pagination cursor for s.
func EncodeCursor(s string) string {
	payload, err := json.Marshal(cursorEnvelope{Version: cursorVersion, Value: s})
	if err != nil {
		// The envelope only contains strings, marshalling cannot fail.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeCursor parses a cursor produced by EncodeCursor. An empty cursor decodes
// to an empty value.
func DecodeCursor(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%w: not base64url", ErrInvalidCursor)
	}
	var envelope cursorEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", fmt.Errorf("%w: not a cursor envelope", ErrInvalidCursor)
	}
	if envelope.Version != cursorVersion {
		return "", fmt.Errorf("%w: unsupported version %d", ErrInvalidCursor, envelope.Version)
	}
	return envelope.Value, nil
}
