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

// The generators are fixed by the BLS12-381 specification, so these are
// checkable against any other implementation.
const (
	generatorG1 = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a1" +
		"4e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
	generatorG2 = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049" +
		"334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051" +
		"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
)

func TestGeneratorsAreThePublishedConstants(t *testing.T) {
	g1 := G1Generator().Bytes()
	g2 := G2Generator().Bytes()

	assert.Equal(t, mustHex(t, generatorG1), g1[:])
	assert.Equal(t, mustHex(t, generatorG2), g2[:])
}
