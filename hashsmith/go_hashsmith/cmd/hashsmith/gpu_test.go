//go:build !gpu && !opencl

package main

import "testing"

// In the default (pure-Go) build there is no GPU backend; detection must report
// that cleanly with a reason, and the seam must never claim a device.
func TestGPUStubDefault(t *testing.T) {
	b, reason := detectGPU()
	if b != nil {
		t.Error("default build must not provide a GPU backend")
	}
	if reason == "" {
		t.Error("detectGPU must explain why GPU is unavailable")
	}
}

func TestLE32(t *testing.T) {
	// little-endian word assembly used to pack md5 targets for the GPU
	if got := le32([]byte{0x01, 0x02, 0x03, 0x04}); got != 0x04030201 {
		t.Errorf("le32 = %08x want 04030201", got)
	}
}

func TestGPUFormatRouting(t *testing.T) {
	for typ, algo := range map[string]int{"md5": 0, "ntlm": 1, "sha256": 2, "sha1": 3, "md4": 4} {
		if got := gpuAlgo(typ); got != algo {
			t.Errorf("gpuAlgo(%q) = %d, want %d", typ, got, algo)
		}
		if got := digestWords(typ); got < 4 {
			t.Errorf("digestWords(%q) = %d", typ, got)
		}
	}
}
