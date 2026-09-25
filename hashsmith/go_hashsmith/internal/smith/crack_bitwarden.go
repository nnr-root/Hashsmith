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

// bitwardenType0Record holds one parsed $bitwarden$0 (encrypted-key)
// target, shared by the scalar verifyBitwarden and the AVX2-batched lane
// hasher (pbkdf2_lane_bitwarden.go).
type bitwardenType0Record struct {
	email string // already lowercased, used as the PBKDF2 salt
	iter  int
	blob  []byte
}

// parseBitwardenType0 parses target, or returns an error identical in
// wording and condition to what verifyBitwarden's "0" branch always
// returned before this was split out.
func parseBitwardenType0(f []string) (bitwardenType0Record, error) {
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return bitwardenType0Record{}, errors.New("invalid Bitwarden iteration count")
	}
	if len(f) != 5 || len(f[2]) == 0 || len(f[2]) > 256 {
		return bitwardenType0Record{}, errors.New("invalid Bitwarden encrypted-key record")
	}
	iv, e1 := hex.DecodeString(f[3])
	blob, e2 := hex.DecodeString(f[4])
	if e1 != nil || e2 != nil || len(iv) != aes.BlockSize || len(blob) < 32 || len(blob) > 4096 || len(blob)%aes.BlockSize != 0 {
		return bitwardenType0Record{}, errors.New("invalid Bitwarden encrypted-key fields")
	}
	return bitwardenType0Record{email: strings.ToLower(f[2]), iter: iter, blob: blob}, nil
}

// bitwardenType0Decrypts is the shared "does this derived key unwrap the
// vault" check. Used by verifyBitwarden for its single derived key and by
// the lane hasher for each of a batch's.
func bitwardenType0Decrypts(r *bitwardenType0Record, key []byte) (bool, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	// Decrypting the final two CBC blocks makes the last block independent
	// of the record IV: its preceding ciphertext block is the effective IV.
	tail := append([]byte(nil), r.blob[len(r.blob)-32:]...)
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(tail, tail)
	for _, value := range tail[16:] {
		if value != aes.BlockSize {
			return false, nil
		}
	}
	return true, nil
}

// bitwardenType2Record holds one parsed $bitwarden$2 (master-password
// hash) target, shared by the scalar verifyBitwarden and the AVX2-batched
// lane hasher. Bitwarden stretches twice: the master key is PBKDF2 over
// the password with the email as salt (one shared salt across a batch),
// and the stored hash is a second PBKDF2 over that master key with the
// PASSWORD as salt — different per candidate, so the lane hasher's second
// round needs the per-lane-salt primitive
// (pbkdf2HMACSHA256DeriveBatchNPerLaneSalt), not the shared-salt one its
// first round uses.
type bitwardenType2Record struct {
	email    []byte
	iter     int
	hashIter int
	want     []byte
}

// parseBitwardenType2 parses target, or returns an error identical in
// wording and condition to what verifyBitwarden's "2" branch always
// returned before this was split out — including the four-vs-five-field
// hashIter handling described above.
func parseBitwardenType2(f []string) (bitwardenType2Record, error) {
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return bitwardenType2Record{}, errors.New("invalid Bitwarden iteration count")
	}
	if len(f) != 4 && len(f) != 5 {
		return bitwardenType2Record{}, errors.New("unsupported Bitwarden record version")
	}
	hashIter, emailField, hashField := 1, 2, 3
	if len(f) == 5 {
		if hashIter, err = strconv.Atoi(f[2]); err != nil || hashIter < 1 || hashIter > maxKDFIterations {
			return bitwardenType2Record{}, errors.New("invalid Bitwarden hash iteration count")
		}
		emailField, hashField = 3, 4
	}
	email, err := base64.StdEncoding.DecodeString(f[emailField])
	if err != nil {
		return bitwardenType2Record{}, errors.New("invalid Bitwarden email")
	}
	want, err := base64.StdEncoding.DecodeString(f[hashField])
	if err != nil || len(want) == 0 {
		return bitwardenType2Record{}, errors.New("invalid Bitwarden hash")
	}
	return bitwardenType2Record{email: email, iter: iter, hashIter: hashIter, want: want}, nil
}

func verifyBitwarden(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$bitwarden$") {
		return false, errors.New("invalid Bitwarden hash (missing $bitwarden$ prefix)")
	}
	f := strings.Split(targetHash[len("$bitwarden$"):], "*")
	if len(f) < 4 {
		return false, errors.New("invalid Bitwarden record")
	}
	if f[0] == "0" {
		r, err := parseBitwardenType0(f)
		if err != nil {
			return false, err
		}
		key := pbkdf2.Key([]byte(candidate), []byte(r.email), r.iter, 32, sha256.New)
		return bitwardenType0Decrypts(&r, key)
	}
	if f[0] != "2" {
		return false, errors.New("unsupported Bitwarden record version")
	}
	r, err := parseBitwardenType2(f)
	if err != nil {
		return false, err
	}
	masterKey := pbkdf2.Key([]byte(candidate), r.email, r.iter, 32, sha256.New)
	got := pbkdf2.Key(masterKey, []byte(candidate), r.hashIter, 32, sha256.New)
	return bytesEqualCT(got, r.want), nil
}
