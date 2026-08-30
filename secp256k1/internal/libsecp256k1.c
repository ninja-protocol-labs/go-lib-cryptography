// This file is the single compilation unit for the vendored libsecp256k1.
//
// cgo only compiles .c files sitting directly in the package directory, never
// in subdirectories. Rather than copying the upstream sources out of the
// submodule, we include them from here so that lib/secp256k1 stays a pristine
// checkout that can be bumped by moving the submodule pointer alone.
//
// Build configuration (module toggles, table sizes) lives in the #cgo CFLAGS
// directives in cgo.go.

#include "lib/secp256k1/src/secp256k1.c"
#include "lib/secp256k1/src/precomputed_ecmult.c"
#include "lib/secp256k1/src/precomputed_ecmult_gen.c"
