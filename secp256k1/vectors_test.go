package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known-answer vectors. The public keys are the published multiples of the
// generator (scalar 1 is G itself) and the digests are SHA-256 of the noted
// messages, so both are checkable against outside sources. The signatures
// were captured while this package was verified byte-for-byte against
// libsecp256k1, and pin RFC 6979 determinism.

type sigVector struct {
	msg    string
	digest string
	sig    string
	der    string
	recID  byte
}

type keyVector struct {
	name   string
	seckey string
	pubkey string
	uncomp string
	sigs   []sigVector
}

var vectors = []keyVector{
	{
		name:   "scalar 1 (generator)",
		seckey: "0000000000000000000000000000000000000000000000000000000000000001",
		pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		uncomp: "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		sigs: []sigVector{
			{
				msg:    "",
				digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				sig: "77c8d336572f6f466055b5f70f433851f8f535f6c4fc71133a6cfd71079d03b7" +
					"0ed9f5eb8aa5b266abac35d416c3207e7a538bf5f37649727d7a9823b1069577",
				der: "3044022077c8d336572f6f466055b5f70f433851f8f535f6c4fc71133a6cfd71079d03b7" +
					"02200ed9f5eb8aa5b266abac35d416c3207e7a538bf5f37649727d7a9823b1069577",
				recID: 1,
			},
			{
				msg:    "abc",
				digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				sig: "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c" +
					"28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1",
				der: "3044022075601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c" +
					"022028ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1",
				recID: 1,
			},
		},
	},
	{
		name:   "scalar 2",
		seckey: "0000000000000000000000000000000000000000000000000000000000000002",
		pubkey: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		uncomp: "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
			"1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
		sigs: []sigVector{
			{
				msg:    "abc",
				digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				sig: "0c0592ae9e9204fb767468714c417fda6663a2f54ae74180a829f91b1ec443e0" +
					"0ca2f735732f71f3cc5b0c2b73315c0cf67ac814200562a6bcbd61af472fe37e",
				der: "304402200c0592ae9e9204fb767468714c417fda6663a2f54ae74180a829f91b1ec443e0" +
					"02200ca2f735732f71f3cc5b0c2b73315c0cf67ac814200562a6bcbd61af472fe37e",
				recID: 0,
			},
		},
	},
	{
		name:   "scalar 3",
		seckey: "0000000000000000000000000000000000000000000000000000000000000003",
		pubkey: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		uncomp: "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" +
			"388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
		sigs: []sigVector{
			{
				msg:    "the quick brown fox jumps over the lazy dog",
				digest: "05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec",
				sig: "8ccbc5ef64189319f82e9bd1bffc11f2dae4f74189da595e62bcdcbc1d053d76" +
					"1485e212b36b89b378befe56e4dd9a949ca19e2ede11890fcad4a0a88229ce92",
				der: "30450221008ccbc5ef64189319f82e9bd1bffc11f2dae4f74189da595e62bcdcbc1d053d76" +
					"02201485e212b36b89b378befe56e4dd9a949ca19e2ede11890fcad4a0a88229ce92",
				recID: 0,
			},
		},
	},
	{
		name:   "scalar 7",
		seckey: "0000000000000000000000000000000000000000000000000000000000000007",
		pubkey: "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
		uncomp: "045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc" +
			"6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da",
		sigs: []sigVector{
			{
				msg:    "",
				digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				sig: "796cb0ad68cbfddf557dbb7963c2262b0ab4a5d4b9e045c045ec930c99d7e7de" +
					"798fe0328395964427e75739d434438e576812192637ea8fe3e40a5f288c2bf3",
				der: "30440220796cb0ad68cbfddf557dbb7963c2262b0ab4a5d4b9e045c045ec930c99d7e7de" +
					"0220798fe0328395964427e75739d434438e576812192637ea8fe3e40a5f288c2bf3",
				recID: 0,
			},
		},
	},
}

func TestVectorPublicKeys(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			k, err := PrivateKeyFromBytes(mustHex(t, v.seckey))
			require.NoError(t, err)

			pub := k.PublicKey().Bytes()
			assert.Equal(t, mustHex(t, v.pubkey), pub[:])

			unc := k.PublicKey().BytesUncompressed()
			assert.Equal(t, mustHex(t, v.uncomp), unc[:])
		})
	}
}

func TestVectorSignatures(t *testing.T) {
	for _, v := range vectors {
		k, err := PrivateKeyFromBytes(mustHex(t, v.seckey))
		require.NoError(t, err)

		for _, s := range v.sigs {
			t.Run(v.name+"/"+s.msg, func(t *testing.T) {
				d := mustHex(t, s.digest)

				sig, err := Sign(k, d)
				require.NoError(t, err)

				b := sig.Bytes()
				assert.Equal(t, mustHex(t, s.sig), b[:], "compact")
				assert.Equal(t, mustHex(t, s.der), sig.DER(), "DER")
				assert.True(t, Verify(k.PublicKey(), d, sig))

				rec, id, err := SignRecoverable(k, d)
				require.NoError(t, err)
				assert.True(t, rec.Equal(sig))
				assert.Equal(t, s.recID, id, "recovery id")

				got, err := Recover(d, sig, s.recID)
				require.NoError(t, err)
				assert.True(t, got.Equal(k.PublicKey()))
			})
		}
	}
}
