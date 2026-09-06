package x25519

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 7748 §6.1: the published X25519 exchange, checked against the raw
// DH value the RFC gives. ECDH returns SHA-256 of it, so the expectation
// is hashed the same way.
func TestRFC7748Exchange(t *testing.T) {
	alice := keyFromHex(t, aliceSeckey)
	bob := keyFromHex(t, bobSeckey)

	gotAlicePub := alice.PublicKey().Bytes()
	gotBobPub := bob.PublicKey().Bytes()
	assert.Equal(t, mustHex(t, alicePubkey), gotAlicePub[:], "alice public key")
	assert.Equal(t, mustHex(t, bobPubkey), gotBobPub[:], "bob public key")

	want := sha256.Sum256(mustHex(t, sharedK))

	fromAlice, err := alice.ECDH(bob.PublicKey())
	require.NoError(t, err)
	fromBob, err := bob.ECDH(alice.PublicKey())
	require.NoError(t, err)

	assert.Equal(t, want, fromAlice)
	assert.Equal(t, want, fromBob)
}
