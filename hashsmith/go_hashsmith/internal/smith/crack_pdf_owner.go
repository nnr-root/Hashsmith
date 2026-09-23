package smith

// PDF owner passwords — Hashcat 25400, "PDF 1.4 - 1.6, user and owner pass".
//
// The Standard security handler stores two credentials. The /U entry proves
// the USER password, which crack.go's verifyPDF already checks. The /O entry
// proves the OWNER password, and it works the other way round: /O is the
// padded user password encrypted under a key derived from the owner password,
// so decrypting it correctly yields something that LOOKS like a padded
// password rather than a value to compare against.
//
// That is why this mode's test is structural. A padded PDF password is up to
// 32 bytes of text followed by the handler's fixed 32-byte padding string,
// truncated to whatever room is left. So the plaintext must be printable
// ASCII up to the point where the padding starts, and the padding must then
// run to the end in order — which is where Hashcat looks too.
//
// One consequence worth stating plainly: an owner password recovered this way
// is reported as the password, and it is not the user password. Both open the
// document; they are different strings.

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// pdfOwnerKeyRounds is the R>=3 key-strengthening count.
	pdfOwnerKeyRounds = 50
	// pdfOwnerRC4Rounds is how many times the /O entry is RC4-wrapped at
	// R>=3, each pass under the key XORed with the round number.
	pdfOwnerRC4Rounds = 20
)

func pdfOwnerKey(candidate string, revision, keySize int) []byte {
	padded := make([]byte, 32)
	n := copy(padded, []byte(candidate))
	copy(padded[n:], pdfPaddingBytes)

	sum := md5.Sum(padded)
	key := sum[:]
	if revision >= 3 {
		for i := 0; i < pdfOwnerKeyRounds; i++ {
			s := md5.Sum(key[:keySize])
			key = s[:]
		}
	}
	return key[:keySize]
}

// pdfLooksLikePaddedPassword reports whether a 32-byte block is a PDF password
// in its padded form: printable text, then the handler's padding string
// running unbroken to the end.
func pdfLooksLikePaddedPassword(plain []byte) bool {
	if len(plain) != 32 {
		return false
	}
	pad := 0
	for i := 0; i < 32; i++ {
		if pad > 0 || plain[i] == pdfPaddingBytes[0] {
			if plain[i] != pdfPaddingBytes[pad] {
				return false
			}
			pad++
			continue
		}
		if !printableASCII(plain[i : i+1]) {
			return false
		}
	}
	// A block that is all text and no padding is a 32-character password,
	// which is legal; one that is all padding is the empty password.
	return true
}

// verifyPDFOwner checks a candidate as the document's OWNER password.
func verifyPDFOwner(target, candidate string) (bool, error) {
	p, err := parsePDFRecord(target)
	if err != nil {
		return false, err
	}
	if len(p.o) != 32 {
		return false, errors.New("PDF /O entry must be 32 bytes")
	}
	key := pdfOwnerKey(candidate, p.revision, p.keySize)

	plain := make([]byte, 32)
	copy(plain, p.o)
	if p.revision >= 3 {
		xkey := make([]byte, len(key))
		for i := pdfOwnerRC4Rounds - 1; i >= 0; i-- {
			for j := range key {
				xkey[j] = key[j] ^ byte(i)
			}
			c, err := rc4.NewCipher(xkey)
			if err != nil {
				return false, err
			}
			c.XORKeyStream(plain, plain)
		}
	} else {
		c, err := rc4.NewCipher(key)
		if err != nil {
			return false, err
		}
		c.XORKeyStream(plain, plain)
	}
	return pdfLooksLikePaddedPassword(plain), nil
}

// verifyPDFUserOrOwner accepts either credential, which is what Hashcat 25400
// does. The user check runs first because it is the cheaper of the two and the
// one a caller usually means.
func verifyPDFUserOrOwner(target, candidate string) (bool, error) {
	if ok, err := verifyPDF(target, candidate); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}
	return verifyPDFOwner(target, candidate)
}

// pdfRecord is the subset of a $pdf$ record the owner check needs.
type pdfRecord struct {
	revision, keySize int
	o                 []byte
}

func parsePDFRecord(target string) (*pdfRecord, error) {
	t := strings.TrimSpace(target)
	if i := strings.IndexByte(t, ':'); i >= 0 {
		t = t[:i]
	}
	if !strings.HasPrefix(t, "$pdf$") || !strings.Contains(t, "*") {
		return nil, errors.New("not a canonical $pdf$ record")
	}
	f := strings.Split(strings.TrimPrefix(t, "$pdf$"), "*")
	if len(f) != 11 {
		return nil, errors.New("PDF record must have 11 fields")
	}
	rev := atoiDefault(f[1], 0)
	bits := atoiDefault(f[2], 0)
	if rev < 2 || bits < 40 {
		return nil, errors.New("PDF revision or key length is out of range")
	}
	keySize := bits / 8
	if keySize < 5 {
		keySize = 5
	}
	if keySize > 16 {
		keySize = 16
	}
	o, err := hex.DecodeString(f[10])
	if err != nil {
		return nil, errors.New("PDF /O entry is not hex")
	}
	return &pdfRecord{revision: rev, keySize: keySize, o: o}, nil
}
