// Package gpubackend holds Hashsmith's GPU backends and the interface they
// implement.
//
// WHY THIS IS A SEPARATE PACKAGE, AND WHY IT MUST STAY ONE:
//
// Go forbids a single package from containing both cgo and hand-written Go
// assembly ("package using cgo has Go assembly file ..."). package main holds
// the NEON and AVX2 vector cores (md5neon_arm64.s, md4neon_arm64.s,
// md5avx2_amd64.s, md4avx2_amd64.s), which are the CPU cracking path and
// several times faster than the scalar one. The GPU backends need cgo, for
// Metal on macOS and OpenCL elsewhere.
//
// Those two requirements cannot share a package. The vector cores stay in main
// because they are generator-produced, heavily tested, and on the default hot
// path; the cgo GPU code lives here instead. Moving these files back into main
// re-breaks `go build -tags gpu` — the ci.yml `gpu-build` job exists to catch
// that.
//
// The interface's methods are EXPORTED for the same structural reason: an
// interface with unexported methods can only be implemented from inside the
// package that declares it, so main's consumers name these across the package
// boundary.
package gpubackend

// Backend is one GPU device able to run Hashsmith's cracking kernels. The
// default build has no implementation (see stub.go); `-tags gpu` compiles the
// Metal backend and `-tags opencl` the OpenCL one.
//
// Every method takes and returns only builtin types, deliberately: it keeps
// this package independent of main, so the dependency runs one way only.
type Backend interface {
	// Name identifies the backend and device (e.g. "Metal (Apple M2)").
	Name() string
	// MD5 writes the 16-byte MD5 digest of each candidate into out[i].
	// len(out) must equal len(candidates). It is the first kernel; further
	// digests (sha1/sha256/ntlm…) extend this interface as kernels are added.
	MD5(candidates []string, out [][16]byte) error
	// MD5Brute searches indices [start, start+count) of the fixed-length brute
	// keyspace over charset (candidates generated in-kernel — no transfer) for
	// one whose MD5 equals target. Returns (matchedIndex, found, error).
	MD5Brute(charset string, wordLen int, target [16]byte, start uint64, count uint32) (uint64, bool, error)
	// MD5Mask is like MD5Brute but with a per-position charset (a parsed mask):
	// candidates are generated in-kernel over the mixed-radix mask keyspace.
	MD5Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	// MD5MaskMulti searches for candidates matching ANY of the sorted targets in
	// one dispatch (multi-hash on the GPU). foundFlag/foundIdx accumulate across
	// dispatches.
	MD5MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	// NTLMMask / NTLMMaskMulti are the NTLM (MD4 of UTF-16LE) equivalents.
	NTLMMask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	NTLMMaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	MD4Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	MD4MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	SHA256Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	SHA256MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	SHA1Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	SHA1MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	// MaskSweepMulti runs a pipelined multi-target sweep (several dispatches in
	// flight) over [start, start+span).
	MaskSweepMulti(algo int, sets [][]byte, targetWords int, targets []uint32, start, span uint64, chunk uint32, foundFlag []uint32, foundIdx []uint64) error
	// Close releases GPU resources.
	Close()
}

// LE32 reads the first four bytes of b as a little-endian uint32. Digest words
// reach the kernels in this order, so both this package and its caller in main
// need it; it lives here so there is one implementation rather than two copies
// either side of the package boundary.
func LE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
