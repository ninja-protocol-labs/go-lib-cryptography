package bn254bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The generators are fixed by the curve, so the public keys of the scalar
// 1 are checkable against any other implementation: 1*G = G.
const (
	generatorG1 = "8000000000000000000000000000000000000000000000000000000000000001"
	generatorG2 = "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" +
		"1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
)

func TestScalarOnePublicKeysAreTheGenerators(t *testing.T) {
	pk, err := PrivateKeyMinPkFromBytes(scalarN(t, 1))
	require.NoError(t, err)
	sk, err := PrivateKeyMinSigFromBytes(scalarN(t, 1))
	require.NoError(t, err)

	g1 := pk.PublicKey().Bytes()
	g2 := sk.PublicKey().Bytes()

	assert.Equal(t, mustHex(t, generatorG1), g1[:])
	assert.Equal(t, mustHex(t, generatorG2), g2[:])
}

// Key and signature known answers. The scalar-1 public keys are the
// generators above, which fixes them independently; the rest were captured
// from this package and pin scalar multiplication, the signing equation
// and the compressed encodings against later change.

type sigVector struct {
	msg       string
	sigMinPk  string
	sigMinSig string
}

type keyVector struct {
	scalar    byte
	pubMinPk  string
	pubMinSig string
	sigs      []sigVector
}

var keyVectors = []keyVector{
	{
		scalar:    1,
		pubMinPk:  generatorG1,
		pubMinSig: generatorG2,
		sigs: []sigVector{
			{
				msg: "",
				sigMinPk: "95d7818c533b52afde777425399b9567140bf7f8f43f4cc56a5e678489740380" +
					"07251f1ec824119ecf8fd2b06ff3b72f32a1aa684a7ab3432667968058c9c2ee",
				sigMinSig: "c7d136df776b599ac7f850d582a5e51f92a4669edb63dfc10b908ea9a54860d6",
			},
			{
				msg: "abc",
				sigMinPk: "dd7cba3049d41b9be8c02261f2bbd0bff3ca601321d89caefe06bd973322942d" +
					"2bf97e47739187aba0c641efd9e919776702af786615b8b8e14e5b8bc6fb5b8f",
				sigMinSig: "a6a6ec3790d5b922ea4abfd023e94e00044aac1d119addde9e57e6cb1c64a3ec",
			},
		},
	},
	{
		scalar:   2,
		pubMinPk: "830644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3",
		pubMinSig: "e03e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad79" +
			"27dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9",
		sigs: []sigVector{
			{
				msg: "",
				sigMinPk: "ce141ba1fbb02e4c9db4e26b61d37b4c3b2d2dd62da19beaa3ce46679d3e44a0" +
					"0d674de0d4f43e1976793596e2ffa1945a03c5a19a59b876ed824f7aa54c20ae",
				sigMinSig: "8898532b791ba5c314cb26abd990da9d838b182f7d9c498a4c810bf5cc4cc398",
			},
			{
				msg: "abc",
				sigMinPk: "ad1861731799860fd0e04ca5a7317ea2c0cc287a345ad4365f8601af140baaed" +
					"04ed335d26e692e07b6056789e7b2951a4c3fe9e5b616606b8afe794d45325db",
				sigMinSig: "94f94311ccd2428339dc93e82d5766f24932c6abca2b290c5fec7271ac4bf5cb",
			},
		},
	},
	{
		scalar:   7,
		pubMinPk: "97072b2ed3bb8d759a5325f477629386cb6fc6ecb801bd76983a6b86abffe078",
		pubMinSig: "a903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455" +
			"224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b308",
		sigs: []sigVector{
			{
				msg: "",
				sigMinPk: "de27a0bbb46c12b347ecc9624432ed81021a47a3a5be71ec7c034fbe9d0f8f3b" +
					"0fb1d99f2e2ef15b33064425f36f4469da8db0e2a55894c962c3f4b239722259",
				sigMinSig: "a7a4bb90c8059e13c5f68a96e369965add0f352053355257684ae383d68a84d7",
			},
			{
				msg: "abc",
				sigMinPk: "8454c7c3305745461fc98a57d924fab9038e75ec641bcb50bffff8acd89c95fb" +
					"1bd7428cac65ff7092f75f591d3e83ea47630e2440893e5388421167e786d710",
				sigMinSig: "eb88226987c6b7c0f91a56190052fedcb43053a4bc7c75d5fa487d944d23f14f",
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
