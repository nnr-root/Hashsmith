// Hand-written, not generated: this is a direct port of Go's own
// internal/cpu/cpu_x86.s CPUID wrapper (internal/cpu is not importable
// outside the standard library — see cpuid_amd64.go's doc comment for why
// this project needs its own copy rather than using golang.org/x/sys/cpu,
// which does not expose SHA-NI on X86 in any version up to and including
// the v0.48.0 this project pins).
#include "textflag.h"

// func cpuidLeaf7(ecxArg uint32) (eax, ebx, ecx, edx uint32)
//
// The single 4-byte input still reserves a full 8-byte argument slot
// before the return values begin — go vet's asmdecl check caught this
// exact offset-by-4 mistake in an earlier draft, which used +4/+8/+12/+16
// (as if the input were not padded); the correct offsets, confirmed by
// vet, are +8/+12/+16/+20.
TEXT ·cpuidLeaf7(SB), NOSPLIT, $0-24
	MOVL $7, AX
	MOVL ecxArg+0(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

// func cpuidMaxLeaf() uint32
TEXT ·cpuidMaxLeaf(SB), NOSPLIT, $0-4
	MOVL $0, AX
	CPUID
	MOVL AX, ret+0(FP)
	RET
