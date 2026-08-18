package main

// Bitcoin / Litecoin wallet.dat cracking.
//
// Bitcoin Core encrypts the wallet master key with AES-256-CBC under a key that
// is stretched from the passphrase with iterated SHA-512:
//
//	digest = sha512(passphrase || salt)
//	repeat (iter-1) times: digest = sha512(digest)
//	AES key = digest[0:32],  IV = digest[32:48]
//
// The 32-byte master key is stored as a 48-byte ciphertext (one full block of
// PKCS#7 padding). A passphrase is verified by decrypting the final ciphertext
// block and checking the padding — no need to recover the key itself.
//
// Accepted format ($bitcoin$ … as produced by bitcoin2smith-style extractors):
//
//	$bitcoin$<cklen>$<ckey>$<slen>$<salt>$<iter>$...

import (
	"crypto/aes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// verifyBitcoin checks a passphrase against a $bitcoin$ target.
func verifyBitcoin(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$bitcoin$") {
		return false, errors.New("invalid bitcoin hash (missing $bitcoin$ prefix)")
	}
	f := strings.Split(targetHash[len("$bitcoin$"):], "$")
	// f: [cklen, ckey, slen, salt, iter, ...]
	if len(f) < 5 {
		return false, errors.New("invalid bitcoin hash (need cklen$ckey$slen$salt$iter)")
	}
	ckey, err := hex.DecodeString(f[1])
	if err != nil || len(ckey) < 32 || len(ckey)%16 != 0 {
		return false, errors.New("invalid bitcoin encrypted master key")
	}
	salt, err := hex.DecodeString(f[3])
	if err != nil {
		return false, errors.New("invalid bitcoin salt")
	}
	iter, err := strconv.Atoi(f[4])
	if err != nil || iter < 1 {
		return false, errors.New("invalid bitcoin iteration count")
	}

	// Iterated SHA-512 key stretch.
	h := sha512.New()
	h.Write([]byte(candidate))
	h.Write(salt)
	digest := h.Sum(nil)
	for i := 1; i < iter; i++ {
		s := sha512.Sum512(digest)
		digest = s[:]
	}
	aesKey := digest[:32]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return false, err
	}
	// Decrypt only the final CBC block: P_last = Dec(C_last) XOR C_prev.
	n := len(ckey)
	cLast := ckey[n-16 : n]
	cPrev := ckey[n-32 : n-16]
	plain := make([]byte, 16)
	block.Decrypt(plain, cLast)
	for i := range plain {
		plain[i] ^= cPrev[i]
	}
	return validBitcoinPadding(plain), nil
}

// validBitcoinPadding matches Bitcoin Core's two real master-key sizes: a
// 32-byte key leaves a full block of 0x10 padding, a 24-byte key leaves 8 bytes
// of 0x08. Restricting to these near-eliminates false positives.
func validBitcoinPadding(lastBlock []byte) bool {
	all10 := true
	for _, b := range lastBlock {
		if b != 0x10 {
			all10 = false
			break
		}
	}
	if all10 {
		return true
	}
	for _, b := range lastBlock[8:] {
		if b != 0x08 {
			return false
		}
	}
	return true
}
