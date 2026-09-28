//go:build amd64

package smith

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestCPUIDLeaf7MatchesTrustedAVX2Bit cross-validates this file's raw CPUID
// assembly against golang.org/x/sys/cpu (a trusted, independently-written
// implementation) on a DIFFERENT bit of the exact same register this
// package's own hasSHANI reads: AVX2 is leaf 7 EBX bit 5, SHA-NI is leaf 7
// EBX bit 29 (see hasSHANI's own doc comment). x/sys/cpu already correctly
// exposes AVX2 (unlike SHA-NI — see cpuid_amd64.go's doc comment for why
// SHA-NI needed this file at all), so agreement here is strong evidence
// this file's CPUID sequence reads the right leaf and the right register,
// which is exactly the evidence needed to trust the SHA-NI bit it also
// reads from that same register.
func TestCPUIDLeaf7MatchesTrustedAVX2Bit(t *testing.T) {
	if cpuidMaxLeaf() < 7 {
		t.Skip("this CPU has no leaf 7; nothing to cross-check")
	}
	_, ebx, _, _ := cpuidLeaf7(0)
	const cpuidAVX2Bit = 1 << 5
	got := ebx&cpuidAVX2Bit != 0
	want := cpu.X86.HasAVX2
	if got != want {
		t.Fatalf("this file's raw CPUID read of leaf 7 EBX bit 5 (AVX2) = %v, "+
			"but golang.org/x/sys/cpu.X86.HasAVX2 = %v — the CPUID sequence "+
			"itself is reading the wrong leaf, wrong register, or wrong bit",
			got, want)
	}
}

// TestHasSHANIRunsWithoutPanicking cannot assert a specific answer — it
// depends on the CPU the test happens to run on — but it does assert the
// whole call path (cpuidMaxLeaf, then conditionally cpuidLeaf7, then the
// bit-29 check in hasSHANI) executes cleanly end to end.
func TestHasSHANIRunsWithoutPanicking(t *testing.T) {
	got := hasSHANI()
	t.Logf("hasSHANI() = %v on this machine", got)
}
