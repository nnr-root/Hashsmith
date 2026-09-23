package main

// Dashlane's local vault file.
//
//	$dashlane$<type>*<32-byte salt>*<length>*<ciphertext>
//
// The key is PBKDF2-HMAC-SHA1 over the password with that salt and 10,204
// iterations — not 10,000, not 10,240; a number with no round shape to it,
// which is the sort of detail that says a constant was typed rather than
// chosen.
//
// What identifies a correct password is the plaintext. Dashlane stores its
// vault as DEFLATE-compressed XML, so a right key inflates to something
// beginning "<?xml version" and a wrong one inflates to nothing at all. That
// makes the check stronger than a tag comparison rather than weaker:
// arbitrary bytes essentially never form a valid DEFLATE stream, and the ones
// that do essentially never spell an XML declaration.
//
// Two details of the container are worth stating because neither is
// deducible. The IV is not stored — it comes out of OpenSSL's EVP_BytesToKey
// run over the PBKDF2 output and the first eight bytes of the salt, with a
// count of one — while the AES key for a type-1 record is the PBKDF2 output
// itself, so the key half of that derivation is computed and then discarded.
// And the compressed stream does not start at the beginning of the plaintext:
// six bytes of Dashlane's own framing come first.

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	dashlanePrefix     = "$dashlane$"
	dashlaneIterations = 10204
	dashlaneSaltLen    = 32
	// John decrypts and inspects this much and no more, which is ample: the
	// XML declaration is the first thing in the stream.
	dashlaneInspect = 128
)

type dashlaneRecord struct {
	kind int
	salt []byte
	data []byte
}

func dashlaneFields(target string) (dashlaneRecord, error) {
	var r dashlaneRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, dashlanePrefix) {
		return r, errors.New("not a Dashlane record")
	}
	f := strings.Split(t[len(dashlanePrefix):], "*")
	if len(f) != 4 {
		return r, errors.New("a Dashlane record is <type>*<salt>*<length>*<ciphertext>")
	}
	var err error
	if r.kind, err = boundedPositiveInt(f[0], "Dashlane record type", 8); err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[1], dashlaneSaltLen, "Dashlane salt"); err != nil {
		return r, err
	}
	length, err := boundedPositiveInt(f[2], "Dashlane ciphertext length", 1<<20)
	if err != nil {
		return r, err
	}
	if r.data, err = hex.DecodeString(f[3]); err != nil || len(r.data) < length {
		return r, errors.New("a Dashlane record carries less ciphertext than it claims")
	}
	r.data = r.data[:length]
	if len(r.data) < dashlaneInspect {
		return r, errors.New("a Dashlane record is too short to check")
	}
	return r, nil
}

func verifyDashlane(target, candidate string) (bool, error) {
	r, err := dashlaneFields(target)
	if err != nil {
		return false, err
	}
	pkey := pbkdf2.Key([]byte(candidate), r.salt, dashlaneIterations, 32, sha1.New)
	key, iv := evpBytesToKey(sha1.New, pkey, r.salt[:8], 1, 32, aes.BlockSize)
	if r.kind == 1 {
		// Type 1 encrypts under the PBKDF2 output directly and keeps only the
		// initialisation vector from the derivation above.
		key = pkey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	out := make([]byte, dashlaneInspect)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, r.data[:dashlaneInspect])

	if r.kind != 1 {
		return bytes.Contains(out, []byte("<?xml version")), nil
	}
	// The DEFLATE stream begins six bytes in. Anything that is not a correct
	// password fails to inflate long before it produces readable bytes, so the
	// error is not worth distinguishing from a wrong answer.
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(out[6:])), dashlaneInspect))
	if err != nil && len(inflated) == 0 {
		return false, nil
	}
	return bytes.Contains(inflated, []byte("<?xml version")), nil
}

func isDashlane(target string) bool {
	_, err := dashlaneFields(target)
	return err == nil
}
