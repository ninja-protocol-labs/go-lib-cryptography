// Package encoding is the public API for the text encodings that
// cryptographic bytes get written down in: hex, base32, base64, base58,
// base58check, and bech32.
//
// # What belongs here
//
// One question decides it: would two different systems implement this
// identically? A radix conversion, an alphabet, a checksum over the bytes
// being encoded — yes. A registry of prefixes, a byte whose value means
// something to one network, the layout of a record — no. Those are the
// property of whatever speaks that protocol, and belong wherever it is
// spoken.
//
// So Base58Check computes and verifies the checksum but knows no version
// bytes; Bech32 encodes a prefix and a data part but knows nothing about
// what the data means. Callers prepend and interpret their own bytes. It is
// the same line this module draws elsewhere: no package here composes a
// primitive into somebody's identifier format.
//
// # Structure serialization is a different layer
//
// Everything here answers "how do I write these bytes as text a human can
// transcribe". Formats that answer "how do I serialize this data structure"
// — RLP, protobuf, a chain's transaction layout — are a layer up and are
// not here, however much they look like encodings.
//
// # Shape
//
// Each codec is a package-level value with no state and no constructor,
// the way encoding/binary exposes BigEndian and LittleEndian, so that
// encoding.Base58.Encode and encoding.Base64.Encode read the same way:
//
//	Encode(b []byte) string
//	Decode(s string) ([]byte, error)
//	DecodeInto(dst []byte, s string) error
//
// DecodeInto is the fixed-length form, and the reason it takes a
// destination rather than returning one: everything in this module returns
// fixed-size arrays, so decoding into [32]byte is the operation that pairs
// with them.
//
//	var k [32]byte
//	err := encoding.Hex.DecodeInto(k[:], s)
//
// It reports an error unless the input decodes to exactly len(dst) bytes,
// which is a check the standard library's decoders leave to the caller.
package encoding

// Base58Alphabet is the alphabet base58 is written in here: the 62
// alphanumerics minus 0, O, I and l, the four that are hard to tell apart
// in print or over a phone. Dropping those four is the entire reason the
// radix is 58 rather than 62.
//
// Other orderings of the same 58 characters exist — Ripple's is the one
// still in use — and this package does not implement them. Nothing in an
// encoded string says which ordering produced it, so a string from one of
// them decodes here to the wrong bytes rather than to an error.
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Invalid marks a byte that is not in Base58Alphabet. 0xff rather
// than 0 because 0 is the legitimate value of '1', the character every
// leading zero byte encodes to — an all-zero 32-byte key is 32 of them.
const base58Invalid = 0xff

// ChecksumLen is the number of checksum bytes base58check appends: the
// first four of the double SHA-256 of the payload.
const ChecksumLen = 4

// Bech32Charset is the bech32 data alphabet, BIP-173's ordering of the 32
// characters. It excludes 1, b, i and o, and the ordering is not
// alphabetical — it is chosen so that the characters most easily confused
// with each other differ in as many bits as possible.
const Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const (
	// bech32Const and bech32mConst are the two checksum constants that
	// distinguish the two encodings. This single value is the entire
	// difference between them.
	bech32Const  = 1
	bech32mConst = 0x2bc830a3

	// separator divides the human-readable part from the data part. It is
	// '1' precisely because '1' is not in the data alphabet, so the last
	// one in the string is unambiguously the separator.
	separator = '1'

	// checksumLen is the number of data characters the checksum occupies.
	checksumLen = 6

	// MaxBech32Len is BIP-173's limit on the whole string. The BCH code's
	// error-detection guarantee — any four errors caught, more caught with
	// overwhelming probability — was computed for lengths up to this, so
	// past it the checksum is weaker than advertised rather than wrong.
	MaxBech32Len = 90
)
