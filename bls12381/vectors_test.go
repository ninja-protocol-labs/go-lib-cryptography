package bls12381

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hash-to-curve known answers from RFC 9380, Appendix J.9.1 (G1) and
// J.10.1 (G2), for the BLS12381G*_XMD:SHA-256_SSWU_RO_ suites. The RFC
// lists affine (x, y); the compressed encodings below were derived from
// those coordinates, big-endian x with the top three bits carrying the
// compression, infinity and y-sign flags (G2 is x_c1 ∥ x_c0).
//
// This is the one part of the package with an authority outside itself:
// hash-to-curve is where a signature scheme most often goes subtly wrong,
// and everything else here — signing, aggregation, verification — is built
// on top of it.

const (
	rfc9380DSTG1 = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
	rfc9380DSTG2 = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

type hashVector struct {
	msg  string
	want string
}

var rfc9380G1 = []hashVector{
	{
		msg: "",
		want: "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1" +
			"",
	},
	{
		msg: "abc",
		want: "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903" +
			"",
	},
	{
		msg: "abcdef0123456789",
		want: "91e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98" +
			"",
	},
	{
		msg: "q128_" + strings.Repeat("q", 128),
		want: "b5f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488" +
			"",
	},
	{
		msg: "a512_" + strings.Repeat("a", 512),
		want: "882aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe" +
			"",
	},
}

var rfc9380G2 = []hashVector{
	{
		msg: "",
		want: "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d" +
			"0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
	},
	{
		msg: "abc",
		want: "939cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8" +
			"02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
	},
	{
		msg: "abcdef0123456789",
		want: "990d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c" +
			"121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
	},
	{
		msg: "q128_" + strings.Repeat("q", 128),
		want: "8934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91" +
			"19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
	},
	{
		msg: "a512_" + strings.Repeat("a", 512),
		want: "91fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569" +
			"01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
	},
}

func TestHashToG1RFC9380(t *testing.T) {
	for _, v := range rfc9380G1 {
		p, err := HashToG1([]byte(v.msg), []byte(rfc9380DSTG1))
		require.NoError(t, err)

		got := p.Bytes()
		assert.Equal(t, mustHex(t, v.want), got[:], "msg of %d bytes", len(v.msg))
	}
}

func TestHashToG2RFC9380(t *testing.T) {
	for _, v := range rfc9380G2 {
		p, err := HashToG2([]byte(v.msg), []byte(rfc9380DSTG2))
		require.NoError(t, err)

		got := p.Bytes()
		assert.Equal(t, mustHex(t, v.want), got[:], "msg of %d bytes", len(v.msg))
	}
}

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

func TestGeneratorsAreThePublishedConstants(t *testing.T) {
	g1 := G1Generator().Bytes()
	g2 := G2Generator().Bytes()

	assert.Equal(t, mustHex(t, generatorG1), g1[:])
	assert.Equal(t, mustHex(t, generatorG2), g2[:])
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
