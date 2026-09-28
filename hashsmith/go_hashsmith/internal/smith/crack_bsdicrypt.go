package smith

import (
	"errors"
	"strings"
)

// BSDi extended DES crypt, Hashcat mode 12400 and John's bsdicrypt.
//
//	_GW..8841inaTltazRsQ
//	^ ^^^^^^^^^^^^^^^^^^
//	| |   |   `- 11 characters of result
//	| |   `----- 4 characters of salt
//	| `--------- 4 characters of iteration count
//	`----------- the '_' that marks the format
//
// It extends traditional DES crypt in three ways, all of which matter for a
// verifier: the iteration count is chosen per hash instead of fixed at 25, the
// salt is 24 bits instead of 12, and a password longer than eight characters
// contributes ALL of itself rather than being truncated.
//
// That last part is the one worth spelling out. Traditional crypt throws away
// everything after the eighth character. BSDi folds each further block in by
// encrypting the zero block under the current key and XORing the result into
// the next eight characters, so "correct horse battery" and "correct horse"
// give different answers — and an implementation that stops at eight passes
// every short-password test there is.
//
// Both numbers are little-endian in crypt's base64 alphabet, which is not the
// usual one: '.' is 0, '/' is 1, then digits, then letters.
const (
	bsdiPrefix     = "_"
	bsdiHashLength = 20 // 1 + 4 + 4 + 11
)

func verifyBSDiCrypt(targetHash, candidate string) (bool, error) {
	got, err := bsdiCryptRaw(candidate, targetHash)
	if err != nil {
		return false, err
	}
	return equalConst([]byte(got), []byte(strings.TrimSpace(targetHash))), nil
}

// bsdiCryptRaw recomputes a full "_" record for candidate, taking the
// iteration count and salt from the target.
func bsdiCryptRaw(candidate, target string) (string, error) {
	target = strings.TrimSpace(target)
	// The WHOLE record is validated, not just the fields this function reads.
	// Without that a corrupt result field — a character outside crypt-64 —
	// simply failed to match, so a damaged record read as "wrong password"
	// and sent the user back to their wordlist instead of to their file.
	if !looksLikeBSDiCrypt(target) {
		return "", errors.New("invalid bsdicrypt hash (need '_' and 19 crypt-base64 characters)")
	}
	rounds, err := bsdiDecodeInt(target[1:5])
	if err != nil {
		return "", err
	}
	saltVal, err := bsdiDecodeInt(target[5:9])
	if err != nil {
		return "", err
	}
	// The count is a 24-bit field, so it cannot ask for more work than that;
	// the check exists because the value comes from an untrusted record.
	if rounds == 0 || rounds > 1<<24 {
		return "", errors.New("bsdicrypt iteration count is out of range")
	}

	pw := []byte(candidate)
	key := bsdiKeyFromBlock(pw, 0)
	ks := desSubkeysFast(key)

	// Every block after the first is folded in by encrypting the KEY UNDER
	// ITSELF and XORing the next eight characters into the result.
	//
	// Two earlier readings of this loop were wrong, and hashcat's published
	// vector could not have caught either: its password is seven characters
	// long and never reaches the loop at all. What caught them was generating
	// records here and handing them to john, which cracked "hashcat" and
	// "abcdefgh" and refused every longer password — the exact signature of a
	// correct first block and a wrong fold.
	for off := 8; off < len(pw); off += 8 {
		key = desEncryptBlockFast(key, &ks, 0)
		key ^= bsdiKeyFromBlock(pw, off)
		ks = desSubkeysFast(key)
	}

	// The iteration count is the whole point of this scheme — a record can ask
	// for millions — so this loop is where all of its cost lives. See
	// desIterateZeroBlock: it is the same loop with the per-iteration IP and
	// FP removed, which for a count in the tens of thousands is nearly all of
	// the permutation work.
	block := desIterateZeroBlock(&ks, descryptSaltMask(uint32(saltVal)), rounds)
	return bsdiPrefix + target[1:9] + descryptPack(block), nil
}

// bsdiKeyFromBlock builds a 64-bit DES key from the eight password characters
// at off, each shifted into the high seven bits of its byte, with absent
// characters left zero.
func bsdiKeyFromBlock(pw []byte, off int) uint64 {
	var key uint64
	for i := 0; i < 8; i++ {
		var b byte
		if off+i < len(pw) {
			b = pw[off+i] << 1
		}
		key = (key << 8) | uint64(b)
	}
	return key
}

// bsdiDecodeInt reads one of the two little-endian crypt-base64 numbers: the
// FIRST character is the least significant six bits, which is the opposite of
// how the result itself is packed.
func bsdiDecodeInt(s string) (int, error) {
	v := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := strings.IndexByte(itoa64, s[i])
		if d < 0 {
			return 0, errors.New("bsdicrypt field has non-crypt-base64 characters")
		}
		v = v<<6 | d
	}
	return v, nil
}

// looksLikeBSDiCrypt reports whether s has the shape of a BSDi extended crypt
// record.
func looksLikeBSDiCrypt(s string) bool {
	if len(s) != bsdiHashLength || s[0] != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if strings.IndexByte(itoa64, s[i]) < 0 {
			return false
		}
	}
	return true
}
