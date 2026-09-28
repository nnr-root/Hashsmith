//go:build !amd64

package smith

// hasSHANI reports whether this CPU has Intel SHA Extensions. Off amd64
// there is no such thing to have — matching hasAVX2/hasSHA256AVX2's own
// generic stubs, so callers never need a build tag of their own.
func hasSHANI() bool { return false }
