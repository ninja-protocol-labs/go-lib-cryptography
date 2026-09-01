package sha3

import (
	"bytes"
	"io"
	"testing"
)

func TestSumSHAKEMatchesKnownAnswer(t *testing.T) {
	want128 := mustDecodeHex(t, abcSHAKE128_32)
	if got := SumSHAKE128(testMsg, len(want128)); !bytes.Equal(got, want128) {
		t.Errorf("SumSHAKE128(%q, %d) = %x, want %x", testMsg, len(want128), got, want128)
	}

	want256 := mustDecodeHex(t, abcSHAKE256_64)
	if got := SumSHAKE256(testMsg, len(want256)); !bytes.Equal(got, want256) {
		t.Errorf("SumSHAKE256(%q, %d) = %x, want %x", testMsg, len(want256), got, want256)
	}
}

func TestSumSHAKEHonoursTheRequestedLength(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 33, 200, 1000} {
		if got := len(SumSHAKE128(testMsg, n)); got != n {
			t.Errorf("SumSHAKE128 returned %d bytes, want %d", got, n)
		}
	}
}

func TestSHAKEOutputIsOneStream(t *testing.T) {
	// Reading more never changes what was already read — a caller asking
	// for 64 bytes gets the same first 32 as one that stopped there. This
	// is what makes an XOF usable as a keystream, and what distinguishes
	// it from a digest recomputed per output length.
	short := SumSHAKE128(testMsg, 32)
	long := SumSHAKE128(testMsg, 64)
	if !bytes.Equal(short, long[:32]) {
		t.Errorf("prefix of the 64-byte output = %x, want %x", long[:32], short)
	}
}

func TestSHAKEStreamingAgreesWithSum(t *testing.T) {
	x := NewSHAKE128()
	x.Write(testMsg[:1])
	x.Write(testMsg[1:])

	got := make([]byte, 32)
	if _, err := io.ReadFull(x, got); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if want := SumSHAKE128(testMsg, 32); !bytes.Equal(got, want) {
		t.Errorf("streaming = %x, SumSHAKE128 = %x", got, want)
	}
}

func TestSHAKEIncrementalReadsConcatenate(t *testing.T) {
	// Two 16-byte reads must give the same 32 bytes as one 32-byte read.
	x := NewSHAKE256()
	x.Write(testMsg)

	var got []byte
	for range 2 {
		buf := make([]byte, 16)
		if _, err := io.ReadFull(x, buf); err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		got = append(got, buf...)
	}
	if want := SumSHAKE256(testMsg, 32); !bytes.Equal(got, want) {
		t.Errorf("two 16-byte reads = %x, want %x", got, want)
	}
}

func TestSHAKEResetIsReusable(t *testing.T) {
	x := NewSHAKE128()
	x.Write([]byte("something else entirely"))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(x, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	x.Reset()
	x.Write(testMsg)
	got := make([]byte, 32)
	if _, err := io.ReadFull(x, got); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if want := SumSHAKE128(testMsg, 32); !bytes.Equal(got, want) {
		t.Errorf("after Reset = %x, want %x", got, want)
	}
}

func TestSHAKEBlockSize(t *testing.T) {
	if got := NewSHAKE128().BlockSize(); got != BlockSizeSHAKE128 {
		t.Errorf("SHAKE128 BlockSize() = %d, want %d", got, BlockSizeSHAKE128)
	}
	if got := NewSHAKE256().BlockSize(); got != BlockSizeSHAKE256 {
		t.Errorf("SHAKE256 BlockSize() = %d, want %d", got, BlockSizeSHAKE256)
	}
}

func TestCSHAKEIsDomainSeparated(t *testing.T) {
	read := func(x *SHAKE) []byte {
		t.Helper()
		x.Write(testMsg)
		out := make([]byte, 32)
		if _, err := io.ReadFull(x, out); err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		return out
	}

	base := read(NewCSHAKE128([]byte("name"), []byte("custom")))
	otherName := read(NewCSHAKE128([]byte("other"), []byte("custom")))
	otherCustom := read(NewCSHAKE128([]byte("name"), []byte("other")))

	if bytes.Equal(base, otherName) {
		t.Error("cSHAKE ignored the function name")
	}
	if bytes.Equal(base, otherCustom) {
		t.Error("cSHAKE ignored the customization string")
	}

	// With both empty, SP 800-185 defines cSHAKE to be plain SHAKE.
	if got, want := read(NewCSHAKE128(nil, nil)), SumSHAKE128(testMsg, 32); !bytes.Equal(got, want) {
		t.Errorf("cSHAKE128(nil, nil) = %x, want SHAKE128's %x", got, want)
	}
}

func TestSHAKEWriteAfterReadPanics(t *testing.T) {
	// Documented in Write: the sponge has switched to squeezing, and
	// quietly absorbing again would produce a stream no other
	// implementation agrees with.
	x := NewSHAKE128()
	x.Write(testMsg)
	if _, err := io.ReadFull(x, make([]byte, 8)); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("Write after Read did not panic")
		}
	}()
	x.Write([]byte("more"))
}
