package blake3

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeriveKeyMatchesOfficialVectors(t *testing.T) {
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			material := vectorInput(c.inputLen)
			want := mustDecodeHex(t, c.deriveKey)

			if got := DeriveKey(vectorContext, material); !bytes.Equal(got[:], want[:KeyLen]) {
				t.Errorf("DeriveKey = %x, want %x", got, want[:KeyLen])
			}

			long, err := DeriveKeyN(vectorContext, material, len(want))
			if err != nil {
				t.Fatalf("DeriveKeyN failed: %v", err)
			}
			if !bytes.Equal(long, want) {
				t.Errorf("DeriveKeyN = %x, want %x", long, want)
			}
		})
	}
}

func TestDeriveKeyNIsAPrefixOfTheSameStream(t *testing.T) {
	material := vectorInput(1025)

	short := DeriveKey(vectorContext, material)
	long, err := DeriveKeyN(vectorContext, material, 128)
	if err != nil {
		t.Fatalf("DeriveKeyN failed: %v", err)
	}
	if !bytes.Equal(short[:], long[:KeyLen]) {
		t.Error("DeriveKey is not the first 32 bytes of DeriveKeyN")
	}
}

func TestContextSeparatesDerivedKeys(t *testing.T) {
	// The point of the mode: one key, many independent subkeys, each bound
	// to a context that must be a hardcoded application constant.
	material := vectorInput(64)

	a := DeriveKey("example.com 2019-12-25 16:18:03 session tokens v1", material)
	b := DeriveKey("example.com 2019-12-25 16:18:03 session tokens v2", material)
	if a == b {
		t.Error("two contexts derived the same key")
	}

	// And a different source key under the same context.
	other := DeriveKey("example.com 2019-12-25 16:18:03 session tokens v1", vectorInput(65))
	if a == other {
		t.Error("two different materials derived the same key")
	}
}

func TestDeriveKeyIsItsOwnMode(t *testing.T) {
	// derive_key is domain-separated from the other two modes by flags in
	// the compression function, so it cannot collide with a plain or keyed
	// hash of the same bytes no matter what the context is.
	material := vectorInput(64)
	derived := DeriveKey(vectorContext, material)

	if plain := Hash256(material).Bytes(); derived == plain {
		t.Error("derive_key output matched a plain hash of the same material")
	}
	key := vectorKeyArray(t)
	if keyed := HashKeyed256(key, material).Bytes(); derived == keyed {
		t.Error("derive_key output matched a keyed hash of the same material")
	}
}

func TestDeriveKeyNRejectsSizeBelowOne(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := DeriveKeyN(vectorContext, nil, n); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("DeriveKeyN(%d) error = %v, want ErrInvalidSize", n, err)
		}
	}
}
