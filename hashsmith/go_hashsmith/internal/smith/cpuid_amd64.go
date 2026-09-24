//go:build amd64

package smith

// hasSHANI reports whether this CPU has Intel SHA Extensions — the check
// the whole PBKDF2 AVX2 core's runtime gate depends on (see the design
// doc's §4.4): the new core is a straightforward regression on any CPU
// that already accelerates SHA-1/256 in hardware (§1's measured finding:
// hardware SHA on this project's own test machine ran 3-4x faster than the
// best hand-written vector alternative), so this must be checked before
// ever dispatching to it.
//
// golang.org/x/sys/cpu (pinned at v0.48.0 in go.mod) does not expose this
// on X86 in any checked version — its X86 struct has HasAVX2 but no SHA
// field at all, confirmed by reading the vendored source directly rather
// than assumed (see the design doc's §4.4 for the correction this
// project's own spec had to make after getting it wrong once). Go's own
// stdlib detects this via the unexported internal/cpu.X86.HasSHA, which
// cannot be imported from outside the standard library. So this file is a
// direct, minimal port of internal/cpu's own CPUID sequence
// (cpuid_amd64.s mirrors internal/cpu/cpu_x86.s's `cpuid` function
// byte-for-byte in structure), checked against exactly the same bit
// internal/cpu checks: CPUID.(EAX=7,ECX=0):EBX, bit 29 — see
// cpu_x86.go's own cpuid_SHA = 1 << 29 and its isSet(ebx7, cpuid_SHA).
func hasSHANI() bool {
	if cpuidMaxLeaf() < 7 {
		// Leaf 7 is unsupported on this CPU; querying it anyway returns
		// whatever the highest supported leaf's data was cached as, which
		// internal/cpu also treats as "nothing past leaf 6 is real" by
		// skipping the query entirely rather than reading noise.
		return false
	}
	_, ebx, _, _ := cpuidLeaf7(0)
	const cpuidSHABit = 1 << 29
	return ebx&cpuidSHABit != 0
}

// cpuidLeaf7 and cpuidMaxLeaf are implemented in cpuid_amd64.s. Neither
// takes or returns a pointer, so there is nothing for go:noescape to say —
// matching internal/cpu's own cpuid/xgetbv, which the same reasoning
// applies to.
func cpuidLeaf7(ecxArg uint32) (eax, ebx, ecx, edx uint32)

func cpuidMaxLeaf() uint32
