// Package internal is the cgo boundary for the vendored blst.
//
// Everything that touches C lives here; the public bls12_381 package consumes
// this one through plain Go types only. Keeping the boundary in a single
// internal package means the exported API never leaks cgo details, and lets a
// pure-Go backend be swapped in later without touching callers.
package internal

/*
#cgo CFLAGS: -I${SRCDIR}/lib/blst/bindings
#cgo CFLAGS: -I${SRCDIR}/lib/blst/build
#cgo CFLAGS: -I${SRCDIR}/lib/blst/src
#cgo CFLAGS: -D__BLST_CGO__
#cgo CFLAGS: -fno-builtin-memcpy -fno-builtin-memset
// blst's own Go bindings gate this the same way: ADX (Intel's ADCX/ADOX,
// available on every x86_64 CPU since 2013's Haswell/Excavator) is faster
// than the portable fallback, at the cost of an illegal-instruction crash
// on anything older. -mno-avx keeps AVX-coded paths off so ADX-only chips
// (e.g. early Zen) aren't excluded by that instead.
#cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// arm64 always uses its own assembly (selected by assembly.S itself via
// __aarch64__), no ADX-equivalent toggle needed. These are the platforms
// blst has no assembly for at all.
#cgo loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__

#include "shim.h"

// Without these, escape analysis has to assume every C function stashes the
// pointers it is handed, so each buffer crossing the boundary is forced onto
// the heap. No shim function retains a caller pointer past its return, and none
// calls back into Go, so both promises hold for the whole surface — including
// shim_pairing_init, which looks like an exception (the pairing context needs
// to remember a DST across many later calls) but isn't: it copies DST into
// the caller-owned ctx buffer itself before returning, precisely so nothing
// here ever needs to keep pointing at Go memory (see shim.c).
#cgo noescape shim_keygen
#cgo nocallback shim_keygen
*/
import "C"
