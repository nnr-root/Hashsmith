//go:build !gpu

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
