package bls12377bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The generators are fixed by the curve, so the public keys of the scalar
// 1 are checkable against any other implementation: 1*G = G.
const (
	generatorG1 = "a08848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5c" +
		"d5481512ffcd394eeab9b16eb21be9ef"
	generatorG2 = "a0ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de" +
		"5cf89984bff76fe6b26bfefa6ea16afe018480be71c785fec89630a2a3841d01" +
		"c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196"
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
				sigMinPk: "a14c893536c5eb003a69d09a7ba30e0827c08ab3841d7b7f17badd829ef7f881" +
					"e4253321b2aad17f12b413c2fba564e5005bac23190ff9b598f87b4a167346e6" +
					"5452cfadc1f4cff8738adda6bfcd91c778f869215215ae5e8875a1c2305f6eaf",
				sigMinSig: "80eec83d8d8999615ae74f05a51b6c4a5a3d3d4e9e8e19748d760a770349b5a0" +
					"162e97373f9bf6d9d272cce36a6da354",
			},
			{
				msg: "abc",
				sigMinPk: "a06df80f7c9f66050be0bccce6cd094f158eff788154cd757b7392787482bd48" +
					"4467ef7eee7a4133879ded2387137ad20102176b0a12878b2282ebd484e76569" +
					"7a339bce5bf05bb1e399686c37b477b69b4af22896cbf6838c156f30372b4099",
				sigMinSig: "a08a8e13f3f877feb3a989f905bab722f95e1c22efcb5c96ca5e9d0f10555ddd" +
					"bae7da66d26da50b8ce4cb0938cbdb20",
			},
		},
	},
	{
		scalar: 2,
		pubMinPk: "80ed453141939e91056edb5a4b5452ed7e61f7f3dd2a4b7ee90e97c9a2301955" +
			"880661656781dc90857aed6d6a416390",
		pubMinSig: "a13314397e45ef715136c17ec005c87a36157abeb1f7a56d3543b7fc8e581da2" +
			"d4ac27a0ceddfa0b1f3f55a777e94d5c016d31b9f625914e7717654ae659d1c0" +
			"cfe58c83f1579a83b1f0717e9e6a41a053e6e88f7f56ec0bc2fd5b6d61713d79",
		sigs: []sigVector{
			{
				msg: "",
				sigMinPk: "a17a034bcb9e59170b0bb884e4c0c717abf833bc513c6e532379058c9f28c71a" +
					"41c4a2e4dbf22bbf91a0dac24d0bf1790159e8b154ac65ea51480aaa6a18e74f" +
					"fe240b94d30d6222e7b10d1e2d0f0167abba9cb8181c2a2d38282d47e204783d",
				sigMinSig: "8140481eb820a9eb8b457fd0163c595f155f115d65b7f6272f9880ce885341bf" +
					"2291605d7c85fcf355c37bf57035d6f8",
			},
			{
				msg: "abc",
				sigMinPk: "817a266fa9cae4ff37f13598bf633764cc83407c77c1b83b91a9d72bfcaf8d29" +
					"3d680ea43ded91fd7be8146182ca979e0009219c7b254bfb4c6fdeabbd0a4016" +
					"544e1fe1b7bc5bb3d16894089fa7b74c64ba9c5c879ba6353dac549fa4d28344",
				sigMinSig: "80d23b4d17378459b14be4b25a54c357c33fc6de4815e408b9617537d1879981" +
					"b86429805bc8a1bbf60ba876ca9dd154",
			},
		},
	},
	{
		scalar: 7,
		pubMinPk: "a0916932fceb94ad7b80fcf492aa5ee0e120410017cc6d17c8962ba2eb799260" +
			"d022c3de5a103e6edbb5ee9135c7f0fa",
		pubMinSig: "818c1f631463ba7a011c2487841e341a50c4c47be271fd206347e1a6b19da670" +
			"7f25723da99b827267b226bb6a8ec2dc0140f206987ef5eaaf9698aa46ecda04" +
			"e79abbcbf4179d039224f78a14b59894f3218e0565fc9bd57bc06707f828e729",
		sigs: []sigVector{
			{
				msg: "",
				sigMinPk: "a025de9e82f024b41448639dc75c6cbf62f573c7b6ed18dbb5a7bcc3f999e8a6" +
					"9a6d128c168a1c56c0317026baaef88600f9b41451657209c9539868d0cd8698" +
					"efbb756a8c04366bed50a192718bbebb42c28fdff754304e3ad440c129dbaacc",
				sigMinSig: "8116301a952844c116896b3ba6cef2217d1b62640b15382f4b4d89e71c37b8a9" +
					"335c8cff856a0fb6a8ac5d91e89b8663",
			},
			{
				msg: "abc",
				sigMinPk: "80f5958b8f2de4bb8ecde0f876ee3532e831aeaf3f1144ac391a745e3084d564" +
					"a43ccde0b683ba95dacb5f5f0d2f13d0004ca5d814accca3b7d3098a015d7c3b" +
					"c8d848537d352b8ec9c7525c8fa74592fa9bd57340469953677395550b3101be",
				sigMinSig: "a09a64857509be78fc632cb92bd0fb1b7f14843a5f2d3031d8cd749562fd8be2" +
					"839b194fe4ea9748ee8a5706b9ce2f02",
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
