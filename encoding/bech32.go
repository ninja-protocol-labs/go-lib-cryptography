package encoding

import "strings"

// Bech32 and Bech32m encode a human-readable prefix and a data part with a
// BCH checksum, per BIP-173 and BIP-350.
//
// # Which one
//
// They differ by one constant, and using the wrong one produces a string
// that looks correct and fails validation at the far end. BIP-350 revised
// bech32 after a weakness was found in its checksum for certain data-part
// lengths, and defines which encoding a given format should use. Which one
// applies is a property of the format being spoken, so it is the caller's
// to know; both are here and neither is the default.
//
// # The data part is five-bit groups
//
// Encode takes data already converted to five-bit values, not bytes. That
// is not an inconvenience to route around: some formats prepend a
// five-bit field before the conversion, which a codec that converted
// internally could not express. Pushing that decision out is what keeps
// this package free of any particular address layout. Use ConvertBits, or
// EncodeBytes for the common case where the payload really is just bytes.
var (
	Bech32  = bech32Codec{constant: bech32Const}
	Bech32m = bech32Codec{constant: bech32mConst}
)

type bech32Codec struct {
	constant uint32
}

// Encode joins hrp and the five-bit data part with a checksum.
//
// hrp must be non-empty US-ASCII in the range 33-126 with no uppercase,
// and every value in data must fit in five bits. The result is checked
// against MaxBech32Len; see EncodeUnlimited for the cases that exceed it.
func (c bech32Codec) Encode(hrp string, data []byte) (string, error) {
	s, err := c.encode(hrp, data)
	if err != nil {
		return "", err
	}
	if len(s) > MaxBech32Len {
		return "", ErrMalformed
	}
	return s, nil
}

// EncodeUnlimited is Encode without the length check.
//
// BIP-173 caps a bech32 string at 90 characters, and some formats built on
// it exceed that on purpose, accepting the weaker guarantee knowingly for
// payloads far larger than an identifier. This exists for those, and says
// so in its name, so that skipping the check is a decision in the code
// rather than a default nobody chose.
func (c bech32Codec) EncodeUnlimited(hrp string, data []byte) (string, error) {
	return c.encode(hrp, data)
}

func (c bech32Codec) encode(hrp string, data []byte) (string, error) {
	if err := validateHRP(hrp); err != nil {
		return "", err
	}
	for _, v := range data {
		if v>>5 != 0 {
			return "", ErrMalformed
		}
	}

	combined := make([]byte, 0, len(data)+checksumLen)
	combined = append(combined, data...)
	combined = append(combined, c.createChecksum(hrp, data)...)

	var b strings.Builder
	b.Grow(len(hrp) + 1 + len(combined))
	b.WriteString(hrp)
	b.WriteByte(separator)
	for _, v := range combined {
		b.WriteByte(Bech32Charset[v])
	}
	return b.String(), nil
}

// EncodeBytes converts data from eight-bit bytes to five-bit groups and
// encodes it — the common case for anything that does not need to place a
// five-bit field ahead of the payload.
func (c bech32Codec) EncodeBytes(hrp string, data []byte) (string, error) {
	converted, err := ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return c.Encode(hrp, converted)
}

// Decode splits s into its prefix and five-bit data part and verifies the
// checksum.
//
// Mixed case is rejected outright, as BIP-173 requires: the encoding is
// defined to be case-insensitive, so a mixed-case string is one that has
// already been mangled. An all-uppercase string is lowered and accepted.
//
// A string longer than MaxBech32Len is rejected; use DecodeUnlimited for
// formats that deliberately exceed it.
func (c bech32Codec) Decode(s string) (string, []byte, error) {
	if len(s) > MaxBech32Len {
		return "", nil, ErrMalformed
	}
	return c.decode(s)
}

// DecodeUnlimited is Decode without the length check. See EncodeUnlimited.
func (c bech32Codec) DecodeUnlimited(s string) (string, []byte, error) {
	return c.decode(s)
}

func (c bech32Codec) decode(s string) (string, []byte, error) {
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, ErrMalformed
	}
	s = lower

	// The separator is not in the data alphabet, so the last one is the
	// real one even when the prefix contains a '1'.
	i := strings.LastIndexByte(s, separator)
	if i < 1 || i+checksumLen+1 > len(s) {
		return "", nil, ErrMalformed
	}

	hrp := s[:i]
	if err := validateHRP(hrp); err != nil {
		return "", nil, err
	}

	data := make([]byte, 0, len(s)-i-1)
	for j := i + 1; j < len(s); j++ {
		d := strings.IndexByte(Bech32Charset, s[j])
		if d < 0 {
			return "", nil, ErrInvalidCharacter
		}
		data = append(data, byte(d))
	}

	if c.polymod(expandHRP(hrp, data)) != c.constant {
		return "", nil, ErrInvalidChecksum
	}
	return hrp, data[:len(data)-checksumLen], nil
}

// DecodeBytes decodes and converts the data part back to eight-bit bytes.
func (c bech32Codec) DecodeBytes(s string) (string, []byte, error) {
	hrp, data, err := c.Decode(s)
	if err != nil {
		return "", nil, err
	}
	converted, err := ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, converted, nil
}

// ConvertBits regroups data from one bit width to another, which is how a
// byte payload becomes a bech32 data part and back.
//
// pad says whether to zero-pad a trailing partial group. Going from eight
// bits to five it must be true, since the last group is usually partial;
// coming back it must be false, and the padding is then checked to be zero
// — a non-zero remainder means the string carried bits that no byte
// payload could have produced.
func ConvertBits(data []byte, from, to uint8, pad bool) ([]byte, error) {
	if from < 1 || from > 8 || to < 1 || to > 8 {
		return nil, ErrMalformed
	}

	var acc uint32
	var bits uint8
	maxv := uint32(1)<<to - 1
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)

	for _, v := range data {
		if uint32(v)>>from != 0 {
			return nil, ErrMalformed
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}

	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, ErrMalformed
	}
	return out, nil
}

// validateHRP holds the human-readable part to BIP-173's rules.
func validateHRP(hrp string) error {
	if hrp == "" {
		return ErrMalformed
	}
	for i := 0; i < len(hrp); i++ {
		ch := hrp[i]
		if ch < 33 || ch > 126 {
			return ErrMalformed
		}
		if ch >= 'A' && ch <= 'Z' {
			return ErrMalformed
		}
	}
	return nil
}

// expandHRP lays the prefix out the way the checksum consumes it: high
// bits, a zero, then low bits, so that the prefix is covered by the same
// BCH code as the data.
func expandHRP(hrp string, data []byte) []byte {
	out := make([]byte, 0, len(hrp)*2+1+len(data))
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return append(out, data...)
}

// polymod is the BCH code over GF(32) that both encodings share; only the
// constant it is compared against differs.
func (c bech32Codec) polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range gen {
			if top>>i&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

func (c bech32Codec) createChecksum(hrp string, data []byte) []byte {
	values := append(expandHRP(hrp, data), 0, 0, 0, 0, 0, 0)
	mod := c.polymod(values) ^ c.constant

	out := make([]byte, checksumLen)
	for i := range out {
		out[i] = byte(mod >> (5 * (5 - i)) & 31)
	}
	return out
}
