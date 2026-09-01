package blake2b

import "golang.org/x/crypto/blake2b"

const (
	// OutputLengthUnknown asks NewXOF for a stream with no length fixed in
	// advance, readable until you stop. Its value is zero — a zero-length
	// XOF being useless, that encoding is free to mean something else.
	//
	// It is not merely "unspecified": BLAKE2Xb binds the requested length
	// into its parameter block, so a stream created this way is a
	// different function from one created with an explicit length, and the
	// two disagree from the first byte.
	OutputLengthUnknown = blake2b.OutputLengthUnknown

	// MaxXOFSize is the largest explicit output length BLAKE2Xb accepts.
	// The value above it, 2³²-1, is reserved as the internal marker for
	// OutputLengthUnknown and is rejected if requested.
	MaxXOFSize = uint32(1<<32 - 2)
)

// XOF is a BLAKE2Xb extendable-output function: absorb input with Write,
// then squeeze output with Read.
//
// Unlike sha3's SHAKE, the total output length is chosen when the XOF is
// constructed and is mixed into the state, so an XOF built for 32 bytes
// and one built for 64 produce unrelated streams. Read returns io.EOF
// once that length has been produced, unless the XOF was created with
// OutputLengthUnknown.
type XOF struct {
	x    blake2b.XOF
	read bool
}

// NewXOF returns a BLAKE2Xb XOF producing size bytes, keyed by key.
//
// size may be OutputLengthUnknown for an unbounded stream, or any length
// up to MaxXOFSize. key may be nil, and is at most MaxKeyLen bytes.
func NewXOF(size uint32, key []byte) (*XOF, error) {
	if len(key) > MaxKeyLen {
		return nil, ErrKeyTooLong
	}
	if size != OutputLengthUnknown && size > MaxXOFSize {
		return nil, ErrXOFSizeTooLarge
	}
	x, err := blake2b.NewXOF(size, key)
	if err != nil {
		return nil, ErrXOFSizeTooLarge
	}
	return &XOF{x: x}, nil
}

// Write absorbs more input. After the first Read it returns
// ErrWriteAfterRead without absorbing anything, since absorbing into a
// squeezing state would produce a stream no other implementation agrees
// with.
//
// The underlying implementation panics in that situation; this reports it
// instead, as everything else in this module does.
func (x *XOF) Write(p []byte) (int, error) {
	if x.read {
		return 0, ErrWriteAfterRead
	}
	return x.x.Write(p)
}

// Read squeezes output. It returns io.EOF once the length the XOF was
// created with has been produced; an XOF created with OutputLengthUnknown
// never reaches that point.
func (x *XOF) Read(p []byte) (int, error) {
	x.read = true
	return x.x.Read(p)
}

// Reset returns x to its initial state, keeping the output length and key
// it was constructed with.
func (x *XOF) Reset() {
	x.x.Reset()
	x.read = false
}

// Clone returns a copy of x in its current state, so that a shared prefix
// can be absorbed once and then extended several ways.
func (x *XOF) Clone() *XOF {
	return &XOF{x: x.x.Clone(), read: x.read}
}
