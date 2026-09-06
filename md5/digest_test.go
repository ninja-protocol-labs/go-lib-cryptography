package md5

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigestFromBytesRoundTrip(t *testing.T) {
	d := Hash([]byte("abc"))
	b := d.Bytes()

	same, err := DigestFromBytes(b[:])
	require.NoError(t, err)
	assert.True(t, d.Equal(same))
}

func TestDigestFromBytesRejectsWrongLength(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, Size-1)},
		{"long", make([]byte, Size+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DigestFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidDigest)
		})
	}
}

// All zeroes is a valid digest, so it must parse; only IsZero flags it.
func TestDigestFromBytesAcceptsAllZero(t *testing.T) {
	d, err := DigestFromBytes(make([]byte, Size))
	require.NoError(t, err)
	assert.True(t, d.IsZero())
}

func TestDigestEqual(t *testing.T) {
	a, b := Hash([]byte("abc")), Hash(nil)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))
}

func TestDigestIsZero(t *testing.T) {
	var uninit Digest
	var nilDigest *Digest

	assert.True(t, uninit.IsZero())
	assert.True(t, nilDigest.IsZero())
	assert.False(t, Hash([]byte("abc")).IsZero())
}

func TestDigestString(t *testing.T) {
	d := Hash([]byte("abc"))
	b := d.Bytes()

	assert.Equal(t, hex.EncodeToString(b[:]), d.String())
	assert.Equal(t, "900150983cd24fb0d6963f7d28e17f72", d.String())
}

// Bytes returns a copy; mutating it must not reach the digest.
func TestDigestBytesIsACopy(t *testing.T) {
	d := Hash([]byte("abc"))

	got := d.Bytes()
	got[0] ^= 0xff

	after := d.Bytes()
	assert.Equal(t, "900150983cd24fb0d6963f7d28e17f72", hex.EncodeToString(after[:]))
}
