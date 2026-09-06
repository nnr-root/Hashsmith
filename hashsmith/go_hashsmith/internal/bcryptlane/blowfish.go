// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is vendored from golang.org/x/crypto/blowfish@v0.31.0 (block.go),
// with the Cipher type renamed to state, decryptBlock removed, and the package
// renamed.
//
// WHY THIS IS VENDORED RATHER THAN IMPORTED: bcrypt's cost is 34,057 Blowfish
// block encryptions, and the only way to make that faster on a CPU is to drive
// several independent candidates through each Feistel round together (see
// eks_lanes.go). blowfish.Cipher's p and s0..s3 fields are unexported, so the
// public ExpandKey(key, *Cipher) API can only advance one candidate at a time.
// Interleaving requires reaching inside the state, which requires owning it.

package bcryptlane

// A state is an instance of Blowfish encryption using a particular key.
//
// This declaration, and initState below, are transcribed verbatim (aside
// from the Cipher -> state rename) from golang.org/x/crypto/blowfish@v0.31.0's
// cipher.go, which is otherwise not vendored here: bcrypt's inner loop never
// calls cipher.go's Encrypt/Decrypt, and those carry 32 of the package's 45
// bounds checks for a byte-slice API this package does not use.
type state struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

func initState(c *state) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
}

// getNextWord returns the next big-endian uint32 value from the byte slice
// at the given position in a circular manner, updating the position.
func getNextWord(b []byte, pos *int) uint32 {
	var w uint32
	j := *pos
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	*pos = j
	return w
}

// expandKey performs a key expansion on the given *state. Specifically, it
// performs the Blowfish algorithm's key schedule which sets up the *state's
// pi and substitution tables for calls to encryptBlock. This is used,
// primarily, to reuse the Blowfish key schedule during bcrypt's set up.
func expandKey(key []byte, c *state) {
	j := 0
	for i := 0; i < 18; i++ {
		// Using inlined getNextWord for performance.
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

// This is similar to expandKey, but folds the salt during the key
// schedule. While expandKey is essentially expandKeyWithSalt with an all-zero
// salt passed in, reusing expandKey turns out to be a place of inefficiency
// and specializing it here is useful.
func expandKeyWithSalt(key []byte, salt []byte, c *state) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getNextWord(key, &j)
	}

	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func encryptBlock(l, r uint32, c *state) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[1]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[2]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[3]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[4]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[5]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[6]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[7]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[8]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[9]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[10]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[11]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[12]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[13]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[14]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[15]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[16]
	xr ^= c.p[17]
	return xr, xl
}

// newSaltedState reproduces blowfish.NewSaltedCipher for bcrypt's use: a key of
// any length (bcrypt keys routinely exceed Blowfish's nominal 56-byte maximum)
// and a non-empty salt. It returns nil for an empty key, matching upstream's
// KeySizeError case, which bcrypt never reaches because it always appends a
// trailing NUL.
func newSaltedState(key, salt []byte) *state {
	if len(key) < 1 {
		return nil
	}
	var c state
	initState(&c)
	expandKeyWithSalt(key, salt, &c)
	return &c
}

// nextWord reads four bytes big-endian from b starting at pos, wrapping
// circularly, which is what upstream getNextWord does with a running cursor.
// Upstream advances the cursor by exactly 4 per call, so the cursor before
// call i is (4*i) mod len(b) — hence an absolute position is equivalent and
// lets several lanes read their own keys independently.
func nextWord(b []byte, pos int) uint32 {
	j := pos % len(b)
	var w uint32
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	return w
}

// saltWord is nextWord for the salt. It is a separate name only so the
// generated code reads clearly at the call site; the semantics are identical.
func saltWord(salt []byte, pos int) uint32 { return nextWord(salt, pos) }
