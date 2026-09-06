package sr25519

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func vrfOK(t *testing.T, k *PrivateKey) (*VRFOutput, *VRFProof) {
	t.Helper()

	out, proof, err := SignVRF(k, testCtx, testMsg)
	require.NoError(t, err)
	return out, proof
}

func TestVRFRoundTrip(t *testing.T) {
	for range 10 {
		k := randKey(t)

		out, proof, err := SignVRF(k, testCtx, testMsg)
		require.NoError(t, err)
		assert.True(t, VerifyVRF(k.PublicKey(), testCtx, testMsg, out, proof))
	}
}

// The output is the function's value: deterministic in key, context and
// message, even though the proof accompanying it is not.
func TestVRFOutputIsDeterministic(t *testing.T) {
	k := aliceKey(t)

	a, _ := vrfOK(t, k)
	b, _ := vrfOK(t, k)

	assert.True(t, a.Equal(b))
}

func TestVRFOutputVariesByInput(t *testing.T) {
	k := aliceKey(t)

	base, _ := vrfOK(t, k)

	other, _, err := SignVRF(k, testCtx, []byte("another"))
	require.NoError(t, err)
	assert.False(t, base.Equal(other), "a different message gave the same output")

	otherCtx, _, err := SignVRF(k, []byte("other ctx"), testMsg)
	require.NoError(t, err)
	assert.False(t, base.Equal(otherCtx), "a different context gave the same output")

	otherKey, _ := vrfOK(t, randKey(t))
	assert.False(t, base.Equal(otherKey), "a different key gave the same output")
}

func TestVerifyVRFRejects(t *testing.T) {
	k := aliceKey(t)
	out, proof := vrfOK(t, k)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, VerifyVRF(randKey(t).PublicKey(), testCtx, testMsg, out, proof))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, VerifyVRF(k.PublicKey(), testCtx, []byte("another"), out, proof))
	})

	t.Run("wrong context", func(t *testing.T) {
		assert.False(t, VerifyVRF(k.PublicKey(), []byte("other"), testMsg, out, proof))
	})

	t.Run("mismatched proof", func(t *testing.T) {
		_, otherProof := vrfOK(t, randKey(t))
		assert.False(t, VerifyVRF(k.PublicKey(), testCtx, testMsg, out, otherProof))
	})

	t.Run("nils", func(t *testing.T) {
		assert.False(t, VerifyVRF(nil, testCtx, testMsg, out, proof))
		assert.False(t, VerifyVRF(k.PublicKey(), testCtx, testMsg, nil, proof))
		assert.False(t, VerifyVRF(k.PublicKey(), testCtx, testMsg, out, nil))
	})
}

func TestVRFRoundTripThroughBytes(t *testing.T) {
	k := aliceKey(t)
	out, proof := vrfOK(t, k)

	ob, pb := out.Bytes(), proof.Bytes()

	sameOut, err := VRFOutputFromBytes(ob[:])
	require.NoError(t, err)
	sameProof, err := VRFProofFromBytes(pb[:])
	require.NoError(t, err)

	assert.True(t, out.Equal(sameOut))
	assert.True(t, proof.Equal(sameProof))
	assert.True(t, VerifyVRF(k.PublicKey(), testCtx, testMsg, sameOut, sameProof))
}

func TestVRFFromBytesRejectsInvalid(t *testing.T) {
	out, proof := vrfOK(t, aliceKey(t))
	ob, pb := out.Bytes(), proof.Bytes()

	t.Run("output", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", ob[:VRFOutputLen-1]},
			{"long", append(ob[:], 0)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, VRFOutputLen)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				_, err := VRFOutputFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidVRFOutput)
			})
		}
	})

	t.Run("proof", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", pb[:VRFProofLen-1]},
			{"long", append(pb[:], 0)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, VRFProofLen)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				_, err := VRFProofFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidVRFProof)
			})
		}
	})
}

func TestVRFZeroValuesAndString(t *testing.T) {
	var (
		uninitOut   VRFOutput
		uninitProof VRFProof
		nilOut      *VRFOutput
		nilProof    *VRFProof
	)

	out, proof := vrfOK(t, aliceKey(t))
	ob, pb := out.Bytes(), proof.Bytes()

	assert.True(t, uninitOut.IsZero())
	assert.True(t, uninitProof.IsZero())
	assert.True(t, nilOut.IsZero())
	assert.True(t, nilProof.IsZero())
	assert.False(t, out.IsZero())
	assert.False(t, proof.IsZero())

	assert.False(t, out.Equal(nil))
	assert.False(t, proof.Equal(nil))

	assert.Equal(t, hex.EncodeToString(ob[:]), out.String())
	assert.Equal(t, hex.EncodeToString(pb[:]), proof.String())
}

func TestSignVRFRejectsNilKey(t *testing.T) {
	_, _, err := SignVRF(nil, testCtx, testMsg)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
}
