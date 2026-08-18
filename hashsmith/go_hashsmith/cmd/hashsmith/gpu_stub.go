//go:build !gpu

package main

// Default build: no GPU. newGPUBackend explains how to enable it. Keeping this
// the default preserves the pure-Go, statically-linked, cross-platform binary.
func newGPUBackend() (gpuBackend, string) {
	return nil, "built without GPU support — rebuild with `go build -tags gpu` (requires cgo + a Metal GPU on macOS)"
}
