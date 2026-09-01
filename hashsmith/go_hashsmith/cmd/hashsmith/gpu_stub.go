package main

import "hashsmith-go/internal/gpubackend"

// newGPUBackend resolves the GPU backend for this build. main itself carries no
// cgo — it cannot, since it holds the vector cores' Go assembly — so the choice
// between the Metal, OpenCL and no-op backends is made by build tags inside
// internal/gpubackend, and this is a thin pass-through.
func newGPUBackend() (gpuBackend, string) {
	return gpubackend.New()
}
