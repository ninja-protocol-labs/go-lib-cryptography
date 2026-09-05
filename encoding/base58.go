package encoding

// Base58Alphabet is the alphabet base58 is normally written in: the 62
// alphanumerics minus 0, O, I and l, the four that are hard to tell apart
// in print or over a phone. Dropping those four is the entire reason the
// radix is 58 rather than 62.
//
// It is the default because almost everything that says "base58" means
// this ordering, not because of who uses it. Other orderings of the same
// 58 characters exist; pass one to NewBase58.
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58 encodes and decodes base58 in Base58Alphabet. For any other
// ordering, build one with NewBase58.
var Base58 = NewBase58(Base58Alphabet)

type base58Codec struct {
	alphabet string
	index    [256]int8
}

// invalid marks a byte that is not in the alphabet. -1 rather than 0
// because 0 is the legitimate value of the first character, which every
// leading zero byte encodes to.
const invalid = -1

// NewBase58 returns a codec over the given 58-character alphabet.
//
// It panics on an alphabet that is not exactly 58 distinct ASCII bytes.
// That is a programming error in a package-level initialiser, not
// something a caller recovers from at runtime — unlike every other failure
// in this package, which is reported.
func NewBase58(alphabet string) base58Codec {
	if len(alphabet) != 58 {
		panic("encoding: base58 alphabet must be exactly 58 bytes")
	}
	c := base58Codec{alphabet: alphabet}
	for i := range c.index {
		c.index[i] = invalid
	}
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		if ch >= 0x80 {
			panic("encoding: base58 alphabet must be ASCII")
		}
		if c.index[ch] != invalid {
			panic("encoding: base58 alphabet has a repeated character")
		}
		c.index[ch] = int8(i)
	}
	return c
}

// Alphabet returns the 58 characters this codec encodes with.
func (c base58Codec) Alphabet() string { return c.alphabet }

// Encode returns b in base58.
//
// Base58 is a radix conversion over the whole input, not a block cipher
// over pieces of it, so there is no padding and the output length is not a
// fixed function of the input length. Leading zero bytes are the exception:
// they carry no magnitude, so each becomes one leading alphabet[0]
// explicitly, which is what makes an all-zero 32-byte key encode to 32
// ones rather than to nothing.
func (c base58Codec) Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	// Upper bound on digits: log(256)/log(58) ≈ 1.365.
	size := (len(b)-zeros)*137/100 + 1
	buf := make([]byte, size)

	// Long division by 58, one input byte at a time, writing digits from
	// the right. length tracks how far left the number reaches so far, so
	// each pass only touches the digits that exist.
	length := 0
	for _, v := range b[zeros:] {
		carry := int(v)
		used := 0
		for j := size - 1; j >= 0 && (carry != 0 || used < length); j-- {
			carry += 256 * int(buf[j])
			buf[j] = byte(carry % 58)
			carry /= 58
			used++
		}
		length = used
	}

	out := make([]byte, 0, zeros+length)
	for range zeros {
		out = append(out, c.alphabet[0])
	}
	for _, d := range buf[size-length:] {
		out = append(out, c.alphabet[d])
	}
	return string(out)
}

// Decode parses s.
//
// It reports ErrInvalidCharacter for any byte outside the alphabet.
//
// Note what that does not catch: a string encoded under one ordering of
// these 58 characters is almost always valid under another, and decodes
// without complaint into different bytes. Nothing in the string says which
// ordering produced it, so a codec built with the wrong alphabet fails
// silently. Knowing which one you meant is the caller's.
func (c base58Codec) Decode(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == c.alphabet[0] {
		zeros++
	}

	// Upper bound on bytes: log(58)/log(256) ≈ 0.733.
	size := (len(s)-zeros)*733/1000 + 1
	buf := make([]byte, size)

	// The inverse of Encode: multiply by 58 and add each digit, writing
	// base-256 limbs from the right.
	length := 0
	for i := zeros; i < len(s); i++ {
		d := c.index[s[i]]
		if d == invalid {
			return nil, ErrInvalidCharacter
		}
		carry := int(d)
		used := 0
		for j := size - 1; j >= 0 && (carry != 0 || used < length); j-- {
			carry += 58 * int(buf[j])
			buf[j] = byte(carry % 256)
			carry /= 256
			used++
		}
		length = used
	}

	out := make([]byte, 0, zeros+length)
	for range zeros {
		out = append(out, 0)
	}
	out = append(out, buf[size-length:]...)
	return out, nil
}

// DecodeInto parses s into dst, which must be exactly the decoded length.
func (c base58Codec) DecodeInto(dst []byte, s string) error {
	b, err := c.Decode(s)
	return decodeInto(dst, b, err)
}
