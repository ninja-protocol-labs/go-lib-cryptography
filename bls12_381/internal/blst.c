// This file is the single compilation unit for the vendored blst.
//
// cgo only compiles .c files sitting directly in the package directory, never
// in subdirectories. Rather than copying the upstream sources out of the
// submodule, we include them from here so that lib/blst stays a pristine
// checkout that can be bumped by moving the submodule pointer alone.
//
// server.c is blst's own single-compilation-unit aggregator (the same file
// its official Go bindings compile via cgo_server.c) — it includes every
// other .c file in src/ in the right order. Build configuration (the
// __BLST_CGO__ macro this depends on, ADX/portable toggles) lives in the
// #cgo CFLAGS directives in shim.go.
#include "lib/blst/src/server.c"
