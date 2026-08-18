package main

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
	"golang.org/x/crypto/ripemd160"
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
			return copy(dst, h.Sum(nil))
		}, true
	case "ntlm":
		return func(dst []byte, s string) int {
			h := md4.New()
			_, _ = h.Write(utf16le(s))
			return copy(dst, h.Sum(nil))
		}, true
	case "ripemd160":
		return func(dst []byte, s string) int {
			h := ripemd160.New()
			_, _ = h.Write([]byte(s))
			return copy(dst, h.Sum(nil))
		}, true
	}
	return nil, false
}

// fastVerifier compares candidates against one precomputed target digest with no
// per-candidate heap allocation.
type fastVerifier struct {
	target [64]byte
	tlen   int
	hash   func(dst []byte, s string) int
}

// newFastVerifier builds a zero-alloc verifier for a raw-digest target, or
// returns false when the type/target is not eligible (caller falls back).
func newFastVerifier(typ, targetHex string) (*fastVerifier, bool) {
	h, ok := rawHasher(typ)
	if !ok {
		return nil, false
	}
	tb, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(tb) == 0 || len(tb) > 64 {
		return nil, false
	}
	f := &fastVerifier{tlen: len(tb), hash: h}
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
