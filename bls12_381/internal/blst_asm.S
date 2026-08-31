// Single compilation unit for blst's precompiled assembly, mirroring
// blst.c's approach for the C sources (and blst's own bindings/go/
// cgo_assembly.S). assembly.S itself branches on platform/arch macros
// (__x86_64__/__aarch64__ × __ELF__/__APPLE__/_WIN64) to pull in the right
// prebuilt .s/.S files under build/{elf,mach-o,coff}/ — no per-platform
// selection needed here.
#include "lib/blst/build/assembly.S"
