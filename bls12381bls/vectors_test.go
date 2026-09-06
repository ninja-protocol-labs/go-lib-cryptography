package bls12381bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Key and signature known answers. The scalar-1 public keys are the
// published BLS12-381 generators (1·G = G), which fixes them independently.
// The rest were captured while this package verified byte-for-byte against
// blst, and pin the layer RFC 9380 does not reach: scalar multiplication,
// the signing equation and the compressed encodings.

const (
	generatorG1 = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a1" +
		"4e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
	generatorG2 = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049" +
		"334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051" +
		"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
)

type keyVector struct {
	scalar    byte
	pubMinPk  string
	pubMinSig string
	sigs      []struct {
		msg       string
		sigMinPk  string
		sigMinSig string
	}
}

var keyVectors = []keyVector{
	{
		scalar:    1,
		pubMinPk:  generatorG1,
		pubMinSig: generatorG2,
		sigs: []struct {
			msg       string
			sigMinPk  string
			sigMinSig string
		}{
			{
				msg: "",
				sigMinPk: "a8aab303e33ed14f4a904004a92bd26ffc969c1d1e7d4b7f0c04150a73e1845a" +
					"911e51a2b2d369d5cef06560c5ac9f5715c01566993d4469805df3e1f29b5364" +
					"81a832bf2751b6908faed6776d062d585521889232999d72b679d6e38bb5cfff",
				sigMinSig: "b2e0e662181bd9f8cd8ef246071357cd07a23c4391e879b49e32084dcc1a2aed" +
					"e123c8e8bfcde92edac229e28b719142",
			},
			{
				msg: "abc",
				sigMinPk: "89d977002d7afe013debf409d2d95f6b49495d92e904874a9b35c2c314cdf95d" +
					"35b61ab2b4218c22ffbb82eb2c4aeef60eb30ce531087cd542cf33a5940752f7" +
					"1d49584b1c6db73277661ca69f253d28ec8e67c45384da8af75a2c9c56a8ff77",
				sigMinSig: "8ab1bfed57bef131b205541860254dd546a592eaa86da31f3128792be5e0a7a8" +
					"23cb6e7f5e4b82e2e0cfc84ef82f5cdb",
			},
		},
	},
	{
		scalar: 2,
		pubMinPk: "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62a" +
			"e28f75bb8f1c7c42c39a8c5529bf0f4e",
		pubMinSig: "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572" +
			"c6c886f6b57ec72a6178288c47c33577" +
			"1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae" +
			"81f14b0bf3611b78c952aacab827a053",
		sigs: []struct {
			msg       string
			sigMinPk  string
			sigMinSig string
		}{
			{
				msg: "abc",
				sigMinPk: "8762c5156e595cfa6b891f95ff774e7df69bd8dba6932b3be18e6d2aa13a3d9e" +
					"c356e88e1d9ff88e65a41db77e6ce3740c970273acdc483123a41479fca2fe48" +
					"924fe4d09ee1375b5927d7e5322b2a1d3574596d9625f0dcd5e3dabb7bdba58a",
				sigMinSig: "82c0f4720eabce7efa18e00d569968bf63263993730c63a1081944b745d3aa4f" +
					"f8301eb72853ee0595e750d4fc1bfbf3",
			},
		},
	},
	{
		scalar: 7,
		pubMinPk: "b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef2" +
			"7b2ae6bcd4c5bc2d54ef5a70627efcb7",
		pubMinSig: "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f" +
			"9a921f1cad1644d4bdb14674247234c8" +
			"049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc" +
			"8b40e32bad1fa85b9c0f368af6d38d3c",
		sigs: []struct {
			msg       string
			sigMinPk  string
			sigMinSig string
		}{
			{
				msg: "",
				sigMinPk: "a960173db67d7d0deb8a9ff10d1a37a20a9d9a6f34f52b2226a631236e825b12" +
					"b778eb7e0341e74e820279c29f7b37dd00952c17e81392436013d33fdf445e72" +
					"483b254efd520363e14b0f5eff214ad93b32a09b22177ba3d0f5bf449446fffb",
				sigMinSig: "b644dc236f4d7a46968872b9cce5dbd99faaa950b45b263b2bb78f68fcc11982" +
					"90bb1f95a0d5c956515120fc55deb312",
			},
		},
	},
}

func TestKeyVectors(t *testing.T) {
	for _, v := range keyVectors {
		pk, err := PrivateKeyMinPkFromBytes(scalarN(t, v.scalar))
		require.NoError(t, err)
		sk, err := PrivateKeyMinSigFromBytes(scalarN(t, v.scalar))
		require.NoError(t, err)

		gotPk := pk.PublicKey().Bytes()
		gotSk := sk.PublicKey().Bytes()
		assert.Equal(t, mustHex(t, v.pubMinPk), gotPk[:], "scalar %d min-pk", v.scalar)
		assert.Equal(t, mustHex(t, v.pubMinSig), gotSk[:], "scalar %d min-sig", v.scalar)

		for _, s := range v.sigs {
			a, err := SignMinPk(pk, []byte(s.msg))
			require.NoError(t, err)
			b, err := SignMinSig(sk, []byte(s.msg))
			require.NoError(t, err)

			ab, bb := a.Bytes(), b.Bytes()
			assert.Equal(t, mustHex(t, s.sigMinPk), ab[:],
				"scalar %d min-pk signature over %q", v.scalar, s.msg)
			assert.Equal(t, mustHex(t, s.sigMinSig), bb[:],
				"scalar %d min-sig signature over %q", v.scalar, s.msg)

			assert.True(t, VerifyMinPk(pk.PublicKey(), []byte(s.msg), a))
			assert.True(t, VerifyMinSig(sk.PublicKey(), []byte(s.msg), b))
		}
	}
}
