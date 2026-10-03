// Package id generates dependency free ULID identifiers.
package id

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Size is the length of an encoded ULID.
const Size = 26

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a new ULID for the current time.
func New() string {
	return NewWithTime(time.Now())
}

// NewWithTime returns a new ULID whose timestamp part is derived from t.
func NewWithTime(t time.Time) string {
	var raw [16]byte
	ms := uint64(t.UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	// crypto/rand.Read never fails: it panics on unrecoverable failures.
	_, _ = rand.Read(raw[6:])
	return Encode(raw)
}

// Encode renders 16 bytes as a 26 character Crockford base32 ULID.
func Encode(raw [16]byte) string {
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[8:16])
	bit := func(pos int) byte {
		if pos < 0 {
			return 0
		}
		if pos < 64 {
			return byte(lo >> uint(pos) & 1)
		}
		return byte(hi >> uint(pos-64) & 1)
	}
	var out [Size]byte
	for i := range Size {
		low := 123 - 5*i
		var char byte
		for k := 4; k >= 0; k-- {
			char = char<<1 | bit(low+k)
		}
		out[i] = alphabet[char]
	}
	return string(out[:])
}
