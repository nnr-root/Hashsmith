package smith

// Bitwarden vault master-password records:
//
//	$bitwarden$0*<iterations>*<email>*<iv-hex>*<encrypted-key-hex>
//	$bitwarden$2*<iterations>*<b64 email>*<b64 hash>
//
//	masterKey = PBKDF2-SHA256(password, email, iterations, 32)
//	hash      = PBKDF2-SHA256(masterKey, password, 1, 32)

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyBitwarden(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$bitwarden$") {
		return false, errors.New("invalid Bitwarden hash (missing $bitwarden$ prefix)")
	}
	f := strings.Split(targetHash[len("$bitwarden$"):], "*")
	if len(f) < 4 {
		return false, errors.New("invalid Bitwarden record")
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return false, errors.New("invalid Bitwarden iteration count")
	}
	if f[0] == "0" {
		if len(f) != 5 || len(f[2]) == 0 || len(f[2]) > 256 {
			return false, errors.New("invalid Bitwarden encrypted-key record")
		}
		iv, e1 := hex.DecodeString(f[3])
		blob, e2 := hex.DecodeString(f[4])
		if e1 != nil || e2 != nil || len(iv) != aes.BlockSize || len(blob) < 32 || len(blob) > 4096 || len(blob)%aes.BlockSize != 0 {
			return false, errors.New("invalid Bitwarden encrypted-key fields")
		}
		key := pbkdf2.Key([]byte(candidate), []byte(strings.ToLower(f[2])), iter, 32, sha256.New)
		block, err := aes.NewCipher(key)
		if err != nil {
			return false, err
		}
		// Decrypting the final two CBC blocks makes the last block independent
		// of the record IV: its preceding ciphertext block is the effective IV.
		tail := append([]byte(nil), blob[len(blob)-32:]...)
		cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(tail, tail)
		for _, value := range tail[16:] {
			if value != aes.BlockSize {
				return false, nil
			}
		}
		return true, nil
	}
	if f[0] != "2" || (len(f) != 4 && len(f) != 5) {
		return false, errors.New("unsupported Bitwarden record version")
	}
	// Bitwarden stretches twice: the master key is PBKDF2 over the password
	// with the email as salt, and the stored hash is a second PBKDF2 over that
	// master key with the password as salt.
	//
	// The four-field spelling leaves the second round count implicit at 1.
	// hashcat -m 23400 carries it explicitly in a fifth field, and its own
	// example record uses 2 — so assuming 1 produced a different hash for
	// every candidate and the record was rejected before it even got that far.
	hashIter, emailField, hashField := 1, 2, 3
	if len(f) == 5 {
		var err error
		if hashIter, err = strconv.Atoi(f[2]); err != nil || hashIter < 1 || hashIter > maxKDFIterations {
			return false, errors.New("invalid Bitwarden hash iteration count")
		}
		emailField, hashField = 3, 4
	}
	email, err := base64.StdEncoding.DecodeString(f[emailField])
	if err != nil {
		return false, errors.New("invalid Bitwarden email")
	}
	want, err := base64.StdEncoding.DecodeString(f[hashField])
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid Bitwarden hash")
	}
	masterKey := pbkdf2.Key([]byte(candidate), email, iter, 32, sha256.New)
	got := pbkdf2.Key(masterKey, []byte(candidate), hashIter, 32, sha256.New)
	return bytesEqualCT(got, want), nil
}
