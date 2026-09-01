package blake2b

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// readXOF absorbs testMsg and squeezes n bytes.
func readXOF(t *testing.T, x *XOF, n int) []byte {
	t.Helper()
	x.Write(testMsg)
	out := make([]byte, n)
	if _, err := io.ReadFull(x, out); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	return out
}

func newXOF(t *testing.T, size uint32, key []byte) *XOF {
	t.Helper()
	x, err := NewXOF(size, key)
	if err != nil {
		t.Fatalf("NewXOF(%d) failed: %v", size, err)
	}
	return x
}

func TestXOFLengthIsBoundIntoTheStream(t *testing.T) {
	// The property that distinguishes BLAKE2Xb from sha3's SHAKE, and the
	// one most likely to surprise: asking for a different total length
	// gives an unrelated stream, not a longer version of the same one.
	short := readXOF(t, newXOF(t, 32, nil), 32)
	long := readXOF(t, newXOF(t, 64, nil), 64)
	if bytes.Equal(short, long[:32]) {
		t.Error("a 32-byte XOF is a prefix of a 64-byte one; the length is not bound in")
	}

	unknown := readXOF(t, newXOF(t, OutputLengthUnknown, nil), 32)
	if bytes.Equal(unknown, short) {
		t.Error("OutputLengthUnknown agreed with an explicit 32-byte XOF")
	}
}

func TestXOFIsDeterministic(t *testing.T) {
	a := readXOF(t, newXOF(t, 64, nil), 64)
	b := readXOF(t, newXOF(t, 64, nil), 64)
	if !bytes.Equal(a, b) {
		t.Error("two XOFs with the same parameters produced different streams")
	}
}

func TestXOFIncrementalReadsConcatenate(t *testing.T) {
	whole := readXOF(t, newXOF(t, 64, nil), 64)

	x := newXOF(t, 64, nil)
	x.Write(testMsg)
	var pieces []byte
	for range 4 {
		buf := make([]byte, 16)
		if _, err := io.ReadFull(x, buf); err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		pieces = append(pieces, buf...)
	}
	if !bytes.Equal(pieces, whole) {
		t.Errorf("four 16-byte reads = %x, want %x", pieces, whole)
	}
}

func TestXOFReadsToEOFAtItsLength(t *testing.T) {
	x := newXOF(t, 32, nil)
	x.Write(testMsg)
	if _, err := io.ReadFull(x, make([]byte, 32)); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	// The declared length is exhausted; reading further must report EOF
	// rather than silently continuing the stream.
	if _, err := x.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("Read past the declared length: err = %v, want io.EOF", err)
	}
}

func TestXOFUnknownLengthKeepsGoing(t *testing.T) {
	x := newXOF(t, OutputLengthUnknown, nil)
	x.Write(testMsg)
	// Well past any fixed length a caller would have declared.
	if _, err := io.ReadFull(x, make([]byte, 4096)); err != nil {
		t.Fatalf("Read failed on an unbounded XOF: %v", err)
	}
}

func TestXOFKeyChangesTheStream(t *testing.T) {
	unkeyed := readXOF(t, newXOF(t, 32, nil), 32)
	keyed := readXOF(t, newXOF(t, 32, testKey), 32)
	if bytes.Equal(unkeyed, keyed) {
		t.Error("the key did not change the XOF stream")
	}
}

func TestXOFResetIsReusable(t *testing.T) {
	want := readXOF(t, newXOF(t, 32, testKey), 32)

	x := newXOF(t, 32, testKey)
	x.Write([]byte("something else entirely"))
	if _, err := io.ReadFull(x, make([]byte, 8)); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	x.Reset()
	if got := readXOF(t, x, 32); !bytes.Equal(got, want) {
		t.Errorf("after Reset = %x, want %x", got, want)
	}
}

func TestXOFCloneSharesThePrefix(t *testing.T) {
	// Absorb a prefix once, then extend it two ways — what Clone is for.
	base := newXOF(t, 32, nil)
	base.Write([]byte("shared prefix"))

	a, b := base.Clone(), base.Clone()
	a.Write([]byte("A"))
	b.Write([]byte("B"))

	outA := make([]byte, 32)
	outB := make([]byte, 32)
	if _, err := io.ReadFull(a, outA); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if _, err := io.ReadFull(b, outB); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if bytes.Equal(outA, outB) {
		t.Error("two clones given different suffixes produced the same stream")
	}

	// A clone must match a fresh XOF fed the whole input.
	want := newXOF(t, 32, nil)
	want.Write([]byte("shared prefixA"))
	expected := make([]byte, 32)
	if _, err := io.ReadFull(want, expected); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(outA, expected) {
		t.Errorf("clone = %x, fresh XOF over the same input = %x", outA, expected)
	}
}

func TestNewXOFRejectsBadParameters(t *testing.T) {
	if _, err := NewXOF(32, make([]byte, MaxKeyLen+1)); !errors.Is(err, ErrKeyTooLong) {
		t.Errorf("NewXOF with an oversized key error = %v, want ErrKeyTooLong", err)
	}
	// 2³²-1 is reserved as the internal marker for OutputLengthUnknown.
	if _, err := NewXOF(MaxXOFSize+1, nil); !errors.Is(err, ErrXOFSizeTooLarge) {
		t.Errorf("NewXOF(2³²-1) error = %v, want ErrXOFSizeTooLarge", err)
	}
	if _, err := NewXOF(MaxXOFSize, nil); err != nil {
		t.Errorf("NewXOF(MaxXOFSize) failed: %v", err)
	}
}

func TestXOFWriteAfterReadIsAnError(t *testing.T) {
	x := newXOF(t, 32, nil)
	x.Write(testMsg)
	if _, err := io.ReadFull(x, make([]byte, 8)); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	n, err := x.Write([]byte("more"))
	if !errors.Is(err, ErrWriteAfterRead) {
		t.Errorf("Write after Read error = %v, want ErrWriteAfterRead", err)
	}
	if n != 0 {
		t.Errorf("Write after Read absorbed %d bytes, want 0", n)
	}

	x.Reset()
	if _, err := x.Write(testMsg); err != nil {
		t.Errorf("Write after Reset failed: %v", err)
	}
}
