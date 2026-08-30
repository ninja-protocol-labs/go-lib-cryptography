package internal

/*
#include "shim.h"
*/
import "C"

import (
	"crypto/rand"
	"sync"
)

// secp256k1_context is expensive to build (it precomputes multiplication
// tables) and is safe for concurrent use once created, so the whole package
// shares one. It is never destroyed: it lives for the life of the process,
// which is what upstream recommends for a library that cannot know when the
// last caller is done.
var (
	ctxOnce sync.Once
	ctx     *C.secp256k1_context
)

// context returns the shared library context, creating it on first use.
func context() *C.secp256k1_context {
	ctxOnce.Do(initContext)
	return ctx
}

func initContext() {
	// The seed randomizes the context, blinding the scalar multiplications
	// used by signing against side-channel attacks.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("secp256k1: reading entropy for context randomization: " + err.Error())
	}

	ctx = C.shim_context_create((*C.uchar)(&seed[0]))
	if ctx == nil {
		panic("secp256k1: context creation failed")
	}
}
