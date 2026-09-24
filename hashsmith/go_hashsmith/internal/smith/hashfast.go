package smith

// Zero-allocation fast paths for the salt-independent raw digests that dominate
// cracking hot loops. Instead of hashing to a hex string and comparing strings
// (a heap allocation and a hex encode per candidate), these hash straight into a
// caller-supplied stack buffer and compare raw bytes — the standard way a
// cracker avoids per-candidate garbage.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
)

// rawHasher returns a function that writes the raw digest of s into dst and
// returns its length, for a fast raw-digest type. The bool is false for types
// without a fast path (the caller then uses the generic verifier).
//
// The []byte(s) conversion inside each hasher does not escape (Sum/Write only
// read it), so the compiler keeps it on the stack — no heap allocation per call.
func rawHasher(typ string) (func(dst []byte, s string) int, bool) {
	switch strings.ToLower(typ) {
	case "md5":
		return func(dst []byte, s string) int { h := md5.Sum([]byte(s)); return copy(dst, h[:]) }, true
	case "sha1":
		return func(dst []byte, s string) int { h := sha1.Sum([]byte(s)); return copy(dst, h[:]) }, true
	case "sha224":
		return func(dst []byte, s string) int { h := sha256.Sum224([]byte(s)); return copy(dst, h[:]) }, true
	case "sha256":
		return func(dst []byte, s string) int { h := sha256.Sum256([]byte(s)); return copy(dst, h[:]) }, true
	case "sha384":
		return func(dst []byte, s string) int { h := sha512.Sum384([]byte(s)); return copy(dst, h[:]) }, true
	case "sha512":
		return func(dst []byte, s string) int { h := sha512.Sum512([]byte(s)); return copy(dst, h[:]) }, true
	case "blake2b":
		return func(dst []byte, s string) int { h := blake2b.Sum512([]byte(s)); return copy(dst, h[:]) }, true
	case "blake2s":
		return func(dst []byte, s string) int { h := blake2s.Sum256([]byte(s)); return copy(dst, h[:]) }, true
	case "md4":
		return func(dst []byte, s string) int {
			h := md4.New()
			_, _ = h.Write([]byte(s))
			var tmp [16]byte
			return copy(dst, h.Sum(tmp[:0]))
		}, true
	case "ntlm":
		return func(dst []byte, s string) int {
			h := md4.New()
			// A stack buffer covering every candidate up to 128 ASCII
			// characters — stdMaxCandidateLen's own figure for "long enough
			// that nothing realistic exceeds it" — so the common case pays
			// no allocation for the UTF-16LE re-encoding; utf16le is the
			// correct, allocating fallback for anything longer or non-ASCII.
			var ubuf [2 * stdMaxCandidateLen]byte
			if v, ok := utf16leInto(ubuf[:], s); ok {
				_, _ = h.Write(v)
			} else {
				_, _ = h.Write(utf16le(s))
			}
			var tmp [16]byte
			return copy(dst, h.Sum(tmp[:0]))
		}, true
	case "ripemd160":
		return func(dst []byte, s string) int {
			h := newRIPEMD160()
			_, _ = h.Write([]byte(s))
			return copy(dst, h.Sum(nil))
		}, true
	}
	return nil, false
}

// rawHasherBytes mirrors rawHasher but takes the candidate as a []byte,
// avoiding the string conversion the batch/benchmark hot loops would
// otherwise pay per candidate.
func rawHasherBytes(typ string) (func(dst, s []byte) int, bool) {
	switch strings.ToLower(typ) {
	case "md5":
		return func(dst, s []byte) int { h := md5.Sum(s); return copy(dst, h[:]) }, true
	case "sha1":
		return func(dst, s []byte) int { h := sha1.Sum(s); return copy(dst, h[:]) }, true
	case "sha224":
		return func(dst, s []byte) int { h := sha256.Sum224(s); return copy(dst, h[:]) }, true
	case "sha256":
		return func(dst, s []byte) int { h := sha256.Sum256(s); return copy(dst, h[:]) }, true
	case "sha384":
		return func(dst, s []byte) int { h := sha512.Sum384(s); return copy(dst, h[:]) }, true
	case "sha512":
		return func(dst, s []byte) int { h := sha512.Sum512(s); return copy(dst, h[:]) }, true
	case "blake2b":
		return func(dst, s []byte) int { h := blake2b.Sum512(s); return copy(dst, h[:]) }, true
	case "blake2s":
		return func(dst, s []byte) int { h := blake2s.Sum256(s); return copy(dst, h[:]) }, true
	case "md4":
		return func(dst, s []byte) int {
			h := md4.New()
			_, _ = h.Write(s)
			var tmp [16]byte
			return copy(dst, h.Sum(tmp[:0]))
		}, true
	case "ntlm":
		return func(dst, s []byte) int {
			h := md4.New()
			// See rawHasher's NTLM case: the same stack-buffer fast path,
			// taking s directly as bytes so the batch/benchmark hot loop
			// this function exists for never pays a string(s) conversion
			// (itself a copy) on top of the encoding.
			var ubuf [2 * stdMaxCandidateLen]byte
			if v, ok := utf16leIntoBytes(ubuf[:], s); ok {
				_, _ = h.Write(v)
			} else {
				_, _ = h.Write(utf16le(string(s)))
			}
			var tmp [16]byte
			return copy(dst, h.Sum(tmp[:0]))
		}, true
	case "ripemd160":
		return func(dst, s []byte) int {
			h := newRIPEMD160()
			_, _ = h.Write(s)
			return copy(dst, h.Sum(nil))
		}, true
	}
	return nil, false
}

// fastVerifier compares candidates against one precomputed target digest with no
// per-candidate heap allocation.
type fastVerifier struct {
	target    [64]byte
	tlen      int
	hash      func(dst []byte, s string) int
	hashBytes func(dst, s []byte) int
}

// newFastVerifier builds a zero-alloc verifier for a raw-digest target, or
// returns false when the type/target is not eligible (caller falls back).
func newFastVerifier(typ, targetHex string) (*fastVerifier, bool) {
	h, ok := rawHasher(typ)
	if !ok {
		return nil, false
	}
	hb, ok := rawHasherBytes(typ)
	if !ok {
		return nil, false
	}
	tb, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(tb) == 0 || len(tb) > 64 {
		return nil, false
	}
	f := &fastVerifier{tlen: len(tb), hash: h, hashBytes: hb}
	copy(f.target[:], tb)
	return f, true
}

func (f *fastVerifier) match(candidate string) bool {
	var buf [64]byte
	n := f.hash(buf[:], candidate)
	if n != f.tlen {
		return false
	}
	// constant-length compare of the digest bytes
	for i := 0; i < n; i++ {
		if buf[i] != f.target[i] {
			return false
		}
	}
	return true
}

// matchBytes is match for a candidate already in a byte slice — the form the
// batch pipeline produces. No string conversion, so no allocation.
func (f *fastVerifier) matchBytes(candidate []byte) bool {
	var buf [64]byte
	n := f.hashBytes(buf[:], candidate)
	if n != f.tlen {
		return false
	}
	for i := 0; i < n; i++ {
		if buf[i] != f.target[i] {
			return false
		}
	}
	return true
}
