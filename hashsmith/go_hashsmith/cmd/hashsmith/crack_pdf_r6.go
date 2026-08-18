package main

// PDF revision 6 (Acrobat X/XI, AES-256; PDF 1.7 ext-3 / PDF 2.0) — the "$pdf$"
// format with '*' separators:
//
//	$pdf$<V>*6*<keybits>*<P>*<meta>*<idlen>*<id>*<Ulen>*<U>*...
//
// The user-password check uses only the U string: U = hash(32) . validationSalt(8)
// . keySalt(8). A correct password reproduces the 32-byte hash via the revision-6
// "hardened hash" (ISO 32000-2 Algorithm 2.B).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

// pdfR6HardenedHash implements ISO 32000-2 Algorithm 2.B.
func pdfR6HardenedHash(password, salt, udata []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write(salt)
	h.Write(udata)
	k := h.Sum(nil)

	for round := 0; ; round++ {
		// K1 = (password . K . udata) repeated 64 times.
		unit := make([]byte, 0, len(password)+len(k)+len(udata))
		unit = append(unit, password...)
		unit = append(unit, k...)
		unit = append(unit, udata...)
		k1 := make([]byte, 0, len(unit)*64)
		for i := 0; i < 64; i++ {
			k1 = append(k1, unit...)
		}
		// E = AES-128-CBC(key=K[0:16], iv=K[16:32], K1), no padding.
		block, err := aes.NewCipher(k[0:16])
		if err != nil {
			return nil
		}
		e := make([]byte, len(k1))
		cipher.NewCBCEncrypter(block, k[16:32]).CryptBlocks(e, k1)

		sum := 0
		for _, b := range e[0:16] {
			sum += int(b)
		}
		switch sum % 3 {
		case 0:
			s := sha256.Sum256(e)
			k = s[:]
		case 1:
			s := sha512.Sum384(e)
			k = s[:]
		default:
			s := sha512.Sum512(e)
			k = s[:]
		}
		if round >= 63 && int(e[len(e)-1]) <= round-32 {
			break
		}
	}
	return k[0:32]
}

func verifyPDFR6(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, "*")
	// $pdf$<V> * <R> * <keybits> * <P> * <meta> * <idlen> * <id> * <Ulen> * <U> * ...
	if len(f) < 9 || !strings.HasPrefix(f[0], "$pdf$") {
		return false, errors.New("invalid PDF R6 hash")
	}
	if f[1] != "5" && f[1] != "6" {
		return false, errors.New("PDF AES verifier supports revision 5 or 6")
	}
	u, err := hex.DecodeString(f[8])
	if err != nil || len(u) < 48 {
		return false, errors.New("invalid PDF U string")
	}
	hashVal := u[0:32]
	vSalt := u[32:40]
	var got []byte
	if f[1] == "5" {
		// Revision 5 (Acrobat 9): a single SHA-256, no hardened loop.
		h := sha256.Sum256(append([]byte(candidate), vSalt...))
		got = h[:]
	} else {
		got = pdfR6HardenedHash([]byte(candidate), vSalt, nil)
	}
	return bytesEqualCT(got, hashVal), nil
}

// isPDFR6: the '*'-separated $pdf$ format with revision 6.
func isPDFR6(s string) bool {
	if !strings.HasPrefix(s, "$pdf$") || !strings.Contains(s, "*") {
		return false
	}
	f := strings.Split(s, "*")
	return len(f) >= 9 && (f[1] == "5" || f[1] == "6")
}
