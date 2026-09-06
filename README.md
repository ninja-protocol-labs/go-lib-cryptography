# go-lib-cryptography

[![CI](https://github.com/ninja-protocol-labs/go-lib-cryptography/actions/workflows/ci.yml/badge.svg)](https://github.com/ninja-protocol-labs/go-lib-cryptography/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ninja-protocol-labs/go-lib-cryptography.svg)](https://pkg.go.dev/github.com/ninja-protocol-labs/go-lib-cryptography)
[![Go Report Card](https://goreportcard.com/badge/github.com/ninja-protocol-labs/go-lib-cryptography)](https://goreportcard.com/report/github.com/ninja-protocol-labs/go-lib-cryptography)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cryptographic primitives in pure Go: elliptic curves and signatures, byte and
field hashes, password KDFs, and the text encodings that go with them.

No cgo, no subpackages, no interfaces to learn — every package sits directly
under the module root and they all have the same shape.

```
go get github.com/ninja-protocol-labs/go-lib-cryptography
```

Requires Go 1.27.

## Packages

| | |
|---|---|
| **Keys and signatures** | `secp256k1` `secp256r1` `ed25519` `ed448` `x25519` `sr25519` |
| | `bn254ecdsa` `bls12377ecdsa` `bls12381ecdsa` |
| | `bn254edwards` `bls12377edwards` `bls12381edwards` |
| | `bn254bls` `bls12377bls` `bls12381bls` |
| **Curves** | `bn254` `bls12377` `bls12381` |
| **Byte hashes** | `sha2` `sha3` `keccak` `blake2b` `blake3` `md5` `ripemd160` |
| **Field hashes** | `bn254mimc` `bls12377mimc` `bls12381mimc` |
| | `bn254poseidon2` `bls12377poseidon2` `bls12381poseidon2` |
| **Key derivation** | `argon2` `scrypt` `pbkdf2` |
| **Encodings** | `encoding` — hex, base32, base58, base58check, base64, bech32 |

## Usage

Hashing. The digest is a value with a name, not a bare array:

```go
d := sha2.Hash256([]byte("abc"))

d.String()    // "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
d.Bytes()     // [32]byte, a copy
d.IsZero()    // false
```

Signing. Signature packages take a digest, not a message — which hash to use
belongs to the protocol:

```go
k, err := secp256k1.GeneratePrivateKey()

d := sha2.Hash256(tx).Bytes()
sig, err := secp256k1.Sign(k, d[:])

secp256k1.Verify(k.PublicKey(), d[:], sig)   // true
```

Ed25519 signs the message itself, because RFC 8032 says so:

```go
k, err := ed25519.GeneratePrivateKey()
sig := ed25519.Sign(k, msg)

ed25519.Verify(k.PublicKey(), msg, sig)      // true
```

Field hashes take one canonical field element per argument, and `Compress` is
the 2-to-1 step a Merkle tree takes at every node:

```go
parent, err := bn254mimc.Compress(left, right)
```

Encoding, with the form that pairs with a fixed-size array:

```go
var k [32]byte
err := encoding.Hex.DecodeInto(k[:], s)

encoding.Base58.Encode(k[:])
```

## Conventions

Input is `[]byte`, output is a fixed-size array. Parsing takes a slice because
that is what arrives from a wire and its length is not yet known; everything
produced comes back as `[N]byte` or a type wrapping one, because the length is
a property of the function.

The exception is output whose length the caller picks, which no type can
carry — `argon2.IDKey`, `scrypt.Key`, `pbkdf2.Key`, `sha3.HashSHAKE128`,
`blake3.DeriveKeyN` — and the `encoding` package, where how many bytes a
string decodes to is a property of the string.

Every value type carries the same four methods:

```go
Bytes() [N]byte     // the encoding, as a copy
Equal(o *T) bool    // nil-safe, constant-time where the value is secret
IsZero() bool       // true for a nil pointer and an uninitialised value
String() string     // lowercase hex
```

`PrivateKey` has no `String`: a secret should not be printable by accident.

This is a convention, not a Go interface. `Bytes` returns `[32]byte`,
`[33]byte`, `[48]byte` or `[64]byte` depending on the type, so no interface
can describe them without erasing the length — and an interface would let two
schemes be substituted for one another, which is what the package split exists
to prevent.

**Same length is not the same type.** SHA-256 and SHA-512/256 are both 32
bytes and unrelated. So are Keccak-256 and SHA3-256, which differ by one
padding byte and are the pair an Ethereum address derivation gets wrong.
`sha2.Digest256`, `sha3.Digest256` and `keccak.Digest256` are three types, so
the mix-up does not compile.

**The curve is part of the function.** MiMC over BN254's scalar field and MiMC
over BLS12-381's are different functions over different fields with different
round constants. They share no digests, so the curve is in the package name
rather than in a parameter.

## Scope

These are primitives. No package here composes one into somebody's identifier
format, transaction layout or derivation path: `base58check` computes the
checksum but knows no version bytes, `bech32` encodes a prefix but knows
nothing about what it means.

## Pure Go

No cgo anywhere, and no assembly this module wrote. It builds for every target
Go supports, `js/wasm` included. CI builds with `CGO_ENABLED=0`, so a cgo
dependency reappearing is a failing build rather than a surprise, and runs the
race detector and cross-compiles for darwin, windows and wasm.

## License

MIT. See [LICENSE](LICENSE).
