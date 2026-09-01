//go:build !gpu && !opencl

package gpubackend

// Default build: no GPU. New explains how to enable it. Keeping this the
// default preserves the pure-Go, statically-linked, cross-platform binary —
// this file carries no cgo, so importing this package costs the default build
// nothing.
func New() (Backend, string) {
	return nil, "built without GPU support — rebuild with `go build -tags gpu` (requires cgo + a Metal GPU on macOS)"
}
