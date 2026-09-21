package main

// RACF KDFAES (IBM z/OS, the modern replacement for RACF DES) — Hashcat 14200.
//
//	$racf-kdfaes$*<userid>*<parameters>*<salt>*<digest>
//
// KDFAES wraps the legacy RACF DES hash in a memory-hard derivation and then
// uses the result as an AES key over the userid. The legacy hash is still in
// there — stage zero is exactly the value mode 8500 stores — which is why this
// shares the EBCDIC tables with RACF and AS/400.
//
// Stage 0 is worth stating plainly because it also simplifies the sibling
// formats: hashcat runs RACF and AS/400 on a DES that omits IP and FP and
// moves both permutations onto the host, but the value the record STORES is
// the composition of all three, which is ordinary DES. So crypto/des computes
// it directly from the EBCDIC-mapped password and the EBCDIC userid block.
//
// The derivation, given mem (the memory factor) and iter (the PBKDF2 count):
//
//	0  key0 = DES(ebcdic(password), ebcdic(userid) padded to 8 with blanks)
//	1  mem times: PBKDF2-SHA256(key0, salt, iter) -> 32 bytes. Each result is
//	   appended to a memory buffer, and the next salt becomes the first 16
//	   bytes of U(iter-1) followed by those 32 bytes. The password stays key0
//	   throughout; only the salt chains.
//	2  mem times: pick a block from the buffer by the last word of the running
//	   key modulo mem, re-key from it with one PBKDF2 round, and overwrite
//	   buffer slot i. This is the memory-hard part: the read index depends on
//	   the key, so the whole buffer has to be resident.
//	3  PBKDF2-SHA256(key, the first (mem-1) blocks of the buffer, iter) -> the
//	   AES-256 key.
//
// Two details that are easy to get wrong and give no signal when wrong. The
// chained salt uses U(iter-1) — the SECOND-to-last PBKDF2 block, not the
// output and not the last block. And the AES plaintext is the userid buffer,
// which is eight bytes of blank-padded EBCDIC zero-extended to sixteen — not
// sixteen bytes of blank padding.

import (
	"crypto/aes"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	racfKDFAESPrefix   = "$racf-kdfaes$*"
	racfKDFAESParamLen = 32
	racfKDFAESUserMax  = 8
	racfKDFAESBlockLen = 32
	// A header may not ask for more than this many memory blocks. Real ones
	// use 8; the cap keeps a malformed record from demanding an allocation.
	racfKDFAESMaxMem  = 1 << 16
	racfKDFAESMaxIter = 10_000_000
)

// racfKDFAESPBKDF2 returns one 32-byte PBKDF2-HMAC-SHA256 block together with
// U(iterations-1), which the chained salt needs.
func racfKDFAESPBKDF2(key, salt []byte, iterations int) (out, secondLast []byte) {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte{0, 0, 0, 1})
	u := h.Sum(nil)
	out = append([]byte(nil), u...)
	secondLast = append([]byte(nil), u...)
	for i := 0; i < iterations-1; i++ {
		if i+1 == iterations-1 {
			secondLast = append([]byte(nil), u...)
		}
		a := hmac.New(sha256.New, key)
		_, _ = a.Write(u)
		u = a.Sum(nil)
		for k := range out {
			out[k] ^= u[k]
		}
	}
	return out, secondLast
}

// racfEBCDICPad renders a userid as EBCDIC, blank-padded to n bytes.
func racfEBCDICPad(s string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = as400ASCIIToEBCDIC[' ']
	}
	for i := 0; i < len(s) && i < n; i++ {
		b[i] = as400ASCIIToEBCDIC[s[i]]
	}
	return b
}

func verifyRACFKDFAES(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if u, p, s, d, ok := johnRACFKDFAESFields(t); ok {
		return verifyRACFKDFAESFields(u, p, s, d, candidate)
	}
	if !strings.HasPrefix(t, racfKDFAESPrefix) {
		return false, errors.New("not a RACF KDFAES record")
	}
	f := strings.Split(strings.TrimPrefix(t, racfKDFAESPrefix), "*")
	if len(f) != 4 {
		return false, errors.New("RACF KDFAES record must be $racf-kdfaes$*<userid>*<params>*<salt>*<digest>")
	}
	return verifyRACFKDFAESFields(f[0], f[1], f[2], f[3], candidate)
}

// johnRACFKDFAESFields reads John's spelling of the same record.
//
// John writes "$racf$*<userid>*<96 hex>" — the same prefix as the legacy DES
// format, with the parameters, salt and digest run together into one field —
// where hashcat writes "$racf-kdfaes$*<userid>*<params>*<salt>*<digest>". The
// three 32-character fields are in the same order, so the split is positional
// and nothing else changes.
func johnRACFKDFAESFields(target string) (user, params, salt, digest string, ok bool) {
	const prefix = "$racf$*"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", "", "", "", false
	}
	f := strings.Split(strings.TrimPrefix(t, prefix), "*")
	if len(f) != 2 || f[0] == "" || len(f[1]) != 96 {
		return "", "", "", "", false
	}
	return f[0], f[1][:32], f[1][32:64], f[1][64:], true
}

// verifyRACFKDFAESFields is the verifier proper, taking the four fields both
// spellings resolve to.
func verifyRACFKDFAESFields(userID, params, saltHex, digestHex, candidate string) (bool, error) {
	if userID == "" || len(userID) > racfKDFAESUserMax {
		return false, errors.New("RACF KDFAES userid must be 1 to 8 characters")
	}
	if len(params) != racfKDFAESParamLen {
		return false, errors.New("RACF KDFAES parameter field must be 32 hex digits")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 16 {
		return false, errors.New("RACF KDFAES salt must be 16 hex-encoded bytes")
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != aes.BlockSize {
		return false, errors.New("RACF KDFAES digest must be 16 hex-encoded bytes")
	}

	// The memory and repetition factors live inside the parameter field as
	// two plain big-endian 16-bit hex values.
	shift, err := strconv.ParseUint(params[16:20], 16, 32)
	if err != nil || shift < 6 || shift > 26 {
		return false, errors.New("RACF KDFAES memory factor is out of range")
	}
	memFac := 1 << (shift - 5) // 2^shift bytes, in 32-byte blocks
	if memFac < 2 || memFac > racfKDFAESMaxMem {
		return false, errors.New("RACF KDFAES memory factor is out of range")
	}
	repFac, err := strconv.ParseUint(params[20:24], 16, 32)
	if err != nil || repFac == 0 {
		return false, errors.New("RACF KDFAES repetition factor is out of range")
	}
	iterations := int(repFac) * 100
	if iterations > racfKDFAESMaxIter {
		return false, errors.New("RACF KDFAES iteration count is out of range")
	}

	// Stage 0: the legacy RACF DES hash.
	desKey := make([]byte, 8)
	for i := range desKey {
		var c byte
		if i < len(candidate) {
			c = candidate[i]
		}
		desKey[i] = racfASCIIToEBCDIC[c]
	}
	block, err := des.NewCipher(desKey)
	if err != nil {
		return false, err
	}
	userBlock := racfEBCDICPad(userID, 8)
	key0 := make([]byte, 8)
	block.Encrypt(key0, userBlock)

	// Stage 1: fill the memory buffer, chaining the salt.
	var memFacBE [4]byte
	binary.BigEndian.PutUint32(memFacBE[:], uint32(memFac))
	chained := append(append([]byte{}, salt...), memFacBE[:]...)
	buffer := make([][]byte, memFac)
	for i := 0; i < memFac; i++ {
		out, secondLast := racfKDFAESPBKDF2(key0, chained, iterations)
		buffer[i] = out
		chained = append(append([]byte{}, secondLast[:16]...), out...)
	}

	// Stage 2: key-dependent reads over the buffer.
	key := append([]byte{}, buffer[memFac-1]...)
	for i := 0; i < memFac; i++ {
		pick := int(binary.BigEndian.Uint32(key[racfKDFAESBlockLen-4:])) % memFac
		h := hmac.New(sha256.New, key)
		_, _ = h.Write(buffer[pick])
		_, _ = h.Write([]byte{0, 0, 0, 1})
		key = h.Sum(nil)
		buffer[i] = key
	}

	// Stage 3: the whole buffer but its last block becomes the salt.
	wide := make([]byte, 0, (memFac-1)*racfKDFAESBlockLen)
	for i := 0; i < memFac-1; i++ {
		wide = append(wide, buffer[i]...)
	}
	final, _ := racfKDFAESPBKDF2(key, wide, iterations)

	// The AES plaintext is the eight-byte userid buffer, zero-extended.
	plain := make([]byte, aes.BlockSize)
	copy(plain, userBlock)
	cipherBlock, err := aes.NewCipher(final)
	if err != nil {
		return false, err
	}
	got := make([]byte, aes.BlockSize)
	cipherBlock.Encrypt(got, plain)
	return subtle.ConstantTimeCompare(got, digest) == 1, nil
}
