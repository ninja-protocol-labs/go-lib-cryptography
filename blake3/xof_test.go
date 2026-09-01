package blake3

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// readXOF absorbs in and squeezes n bytes.
func readXOF(t *testing.T, x *XOF, in []byte, n int) []byte {
	t.Helper()
	x.Write(in)
	out := make([]byte, n)
	if _, err := io.ReadFull(x, out); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	return out
}

func TestXOFMatchesOfficialVectors(t *testing.T) {
	// The XOF is not a separate function — it is the same stream Sum256
	// and Sum512 return prefixes of, so the upstream vectors apply to it
	// directly.
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			want := mustDecodeHex(t, c.hash)
			if got := readXOF(t, NewXOF(), vectorInput(c.inputLen), len(want)); !bytes.Equal(got, want) {
				t.Errorf("XOF = %x, want %x", got, want)
			}
		})
	}
}

func TestKeyedXOFMatchesOfficialVectors(t *testing.T) {
	key := vectorKeyArray(t)
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			want := mustDecodeHex(t, c.keyedHash)
			if got := readXOF(t, NewKeyedXOF(key), vectorInput(c.inputLen), len(want)); !bytes.Equal(got, want) {
				t.Errorf("keyed XOF = %x, want %x", got, want)
			}
		})
	}
}

func TestXOFAgreesWithTheSumFunctions(t *testing.T) {
	in := vectorInput(2049)

	stream := readXOF(t, NewXOF(), in, Size512)
	if s256 := Sum256(in); !bytes.Equal(stream[:Size256], s256[:]) {
		t.Error("the XOF's first 32 bytes are not Sum256")
	}
	if s512 := Sum512(in); !bytes.Equal(stream, s512[:]) {
		t.Error("the XOF's first 64 bytes are not Sum512")
	}
}

func TestXOFIncrementalReadsConcatenate(t *testing.T) {
	in := vectorInput(1025)
	whole := readXOF(t, NewXOF(), in, 128)

	x := NewXOF()
	x.Write(in)
	var pieces []byte
	for range 8 {
		buf := make([]byte, 16)
		if _, err := io.ReadFull(x, buf); err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		pieces = append(pieces, buf...)
	}
	if !bytes.Equal(pieces, whole) {
		t.Errorf("eight 16-byte reads = %x, want %x", pieces, whole)
	}
}

// TestXOFDoesNotExposeSeek is a compile-time guard, not a behaviour test:
// if a future backend fixes seeking and someone adds the method back, this
// stops compiling and the doc on XOF has to be revisited with it.
//
// The backend's own Seek is wrong today — see the note on XOF — so the
// method is deliberately absent.
func TestXOFDoesNotExposeSeek(t *testing.T) {
	var x any = NewXOF()
	if _, ok := x.(io.Seeker); ok {
		t.Error("XOF exposes Seek; see the note on XOF before keeping it")
	}
}

func TestXOFResetKeepsTheKey(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(64)
	want := readXOF(t, NewKeyedXOF(key), in, 64)

	x := NewKeyedXOF(key)
	x.Write([]byte("something else entirely"))
	if _, err := io.ReadFull(x, make([]byte, 8)); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	x.Reset()
	if got := readXOF(t, x, in, 64); !bytes.Equal(got, want) {
		t.Errorf("after Reset = %x, want %x", got, want)
	}
}

func TestXOFWriteAfterReadIsAnError(t *testing.T) {
	x := NewXOF()
	x.Write(vectorInput(64))
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

	// Reset must lift it.
	x.Reset()
	if _, err := x.Write(vectorInput(64)); err != nil {
		t.Errorf("Write after Reset failed: %v", err)
	}
}
