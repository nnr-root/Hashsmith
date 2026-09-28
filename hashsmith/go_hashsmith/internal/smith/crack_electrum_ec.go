package smith

// Electrum wallet, salt types 4 and 5 — Hashcat 21700 and 21800.
//
//	$electrum$4*<33-byte pubkey>*<data>*<32-byte MAC>
//	$electrum$5*<33-byte pubkey>*<data>*<32-byte MAC>
//
// Both derive the same way. Electrum runs PBKDF2-HMAC-SHA512 over the
// password with NO SALT — an empty salt, 1024 iterations — reduces the
// 64-byte result modulo the secp256k1 group order, and multiplies the
// wallet's stored public key by that scalar. SHA-512 of the compressed
// result is the key material. The elliptic-curve step is what makes this
// slow: one point multiplication per candidate, which no amount of hashing
// cleverness avoids.
//
// The two types diverge at the check, and not symmetrically:
//
//	type 4  HMAC-SHA256 over the data with the upper half of the SHA-512.
//	        An exact authenticator: a candidate is right or it is not.
//
//	type 5  AES-128-CBC decrypt the data, zlib inflate it, and decide from
//	        what comes out. There is NO authenticator in this format. hashcat
//	        accepts a candidate when the plaintext inflates, looks like JSON
//	        (leading brace, enough quotes and colons), contains no stray
//	        control characters, and has Shannon entropy between 3 and 6.
//
// The type 5 rule is reproduced here exactly, including the entropy bounds
// and the odd detail that the entropy is measured over a whole number of
// 32-bit words rather than the whole output. It is a heuristic, so it can in
// principle accept a wrong password — but it is hashcat's heuristic, and
// diverging from it would mean disagreeing about which candidates are
// "correct" for a format that has no ground truth to appeal to. In practice
// the zlib header rejects essentially everything: a wrong password fails
// before any of the JSON tests run.

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	electrumPrefix     = "$electrum$"
	electrumIterations = 1024
	electrumPubKeyLen  = 33
	electrumMACLen     = 32
	electrumInflateMax = 1024
	electrumMinEntropy = 3.0
	electrumMaxEntropy = 6.0
)

// secpDecompress recovers the full point from a 33-byte compressed encoding.
// y = sqrt(x^3 + 7); secp256k1's p is 3 mod 4, so the square root is a single
// exponentiation by (p+1)/4.
func secpDecompress(b []byte) (secpPoint, error) {
	if len(b) != electrumPubKeyLen || (b[0] != 2 && b[0] != 3) {
		return secpPoint{}, errors.New("not a compressed secp256k1 point")
	}
	x := new(big.Int).SetBytes(b[1:])
	if x.Sign() == 0 || x.Cmp(secpP) >= 0 {
		return secpPoint{}, errors.New("secp256k1 point is out of range")
	}
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	y2.Add(y2, big.NewInt(7))
	y2.Mod(y2, secpP)

	e := new(big.Int).Add(secpP, big.NewInt(1))
	e.Rsh(e, 2)
	y := new(big.Int).Exp(y2, e, secpP)

	// Reject an x that is not on the curve: squaring must return y2.
	if check := new(big.Int).Mul(y, y); check.Mod(check, secpP).Cmp(y2) != 0 {
		return secpPoint{}, errors.New("secp256k1 point is not on the curve")
	}
	if y.Bit(0) != uint(b[0]&1) {
		y.Sub(secpP, y)
	}
	return secpPoint{x, y}, nil
}

// secpScalarMult multiplies an arbitrary point, as distinct from
// secpScalarBaseMult which is fixed to the generator.
func secpScalarMult(p secpPoint, k *big.Int) secpPoint {
	result := secpPoint{}
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = secpDouble(result)
		if k.Bit(i) != 0 {
			result = secpAdd(result, p)
		}
	}
	return result
}

// electrumKeyMaterial is the stage both salt types share.
func electrumKeyMaterial(candidate string, pubKey []byte) ([sha512.Size]byte, error) {
	point, err := secpDecompress(pubKey)
	if err != nil {
		return [sha512.Size]byte{}, err
	}
	// Empty salt: Electrum passes b"" to PBKDF2.
	derived := pbkdf2.Key([]byte(candidate), nil, electrumIterations, 64, sha512.New)
	tweak := new(big.Int).SetBytes(derived)
	tweak.Mod(tweak, secpN)

	product := secpScalarMult(point, tweak)
	if product.x == nil {
		return [sha512.Size]byte{}, errors.New("secp256k1 multiplication reached the point at infinity")
	}
	compressed := make([]byte, electrumPubKeyLen)
	compressed[0] = 2
	if product.y.Bit(0) != 0 {
		compressed[0] = 3
	}
	product.x.FillBytes(compressed[1:])
	return sha512.Sum512(compressed), nil
}

// electrumEntropy is Shannon entropy in bits per byte, over a whole number of
// 32-bit words — hashcat measures it that way, so the tail bytes of an output
// whose length is not a multiple of four do not count.
func electrumEntropy(b []byte) float64 {
	b = b[:len(b)/4*4]
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	entropy := 0.0
	for _, n := range counts {
		if n == 0 {
			continue
		}
		w := float64(n) / float64(len(b))
		entropy += -w * math.Log2(w)
	}
	return entropy
}

// electrumLooksLikeWallet is hashcat's acceptance test for salt type 5: a
// control-character gate, then EITHER a shape-and-entropy test OR a literal
// match on the indentation Electrum's JSON writer produces. The second branch
// is what accepts hashcat's own published record — its wallet's first key is
// long enough that no colon falls inside the sixteen-byte window the first
// branch looks at, so the shape test alone rejects it.
func electrumLooksLikeWallet(out []byte) bool {
	if len(out) < 2 {
		return false
	}
	for i := 1; i < len(out); i++ {
		c := out[i]
		if c == '\t' || c == '\r' || c == '\n' || c >= 0x20 {
			continue
		}
		// A control character is tolerated only as part of an escape.
		if out[i-1] != '\\' {
			return false
		}
	}
	if electrumHasWalletPrefix(out) {
		return true
	}
	if out[0] != '{' {
		return false
	}
	var quotesHead, colonsHead, quotesAll, colonsAll int
	for i := 1; i < len(out); i++ {
		switch out[i] {
		case '"':
			quotesAll++
			if i < 16 {
				quotesHead++
			}
		case ':':
			colonsAll++
			if i < 16 {
				colonsHead++
			}
		}
	}
	if quotesHead < 1 || colonsHead < 1 || quotesAll < 4 || colonsAll < 3 {
		return false
	}
	e := electrumEntropy(out)
	return e >= electrumMinEntropy && e <= electrumMaxEntropy
}

// electrumHasWalletPrefix matches the exact opening Electrum writes:
// "{\n    \"" or the same with CRLF.
func electrumHasWalletPrefix(out []byte) bool {
	return bytes.HasPrefix(out, []byte("{\n    \"")) || bytes.HasPrefix(out, []byte("{\r\n    \""))
}

func verifyElectrumEC(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, electrumPrefix) {
		return false, errors.New("not an Electrum record")
	}
	f := strings.Split(strings.TrimPrefix(t, electrumPrefix), "*")
	if len(f) != 4 {
		return false, errors.New("Electrum record must have 4 fields")
	}
	saltType := f[0]
	if saltType != "4" && saltType != "5" {
		return false, errors.New("Hashsmith supports Electrum salt types 4 and 5")
	}
	pubKey, err := hex.DecodeString(f[1])
	if err != nil || len(pubKey) != electrumPubKeyLen {
		return false, errors.New("Electrum public key must be 33 hex-encoded bytes")
	}
	data, err := hex.DecodeString(f[2])
	if err != nil || len(data) == 0 {
		return false, errors.New("Electrum data must be hex")
	}
	mac, err := hex.DecodeString(f[3])
	if err != nil || len(mac) != electrumMACLen {
		return false, errors.New("Electrum MAC must be 32 hex-encoded bytes")
	}

	key, err := electrumKeyMaterial(candidate, pubKey)
	if err != nil {
		return false, err
	}

	if saltType == "4" {
		h := hmac.New(sha256.New, key[32:])
		h.Write(data)
		return hmac.Equal(h.Sum(nil), mac), nil
	}

	// Salt type 5: decrypt, inflate, and judge.
	if len(data)%aes.BlockSize != 0 {
		return false, errors.New("Electrum data must be a whole number of AES blocks")
	}
	block, err := aes.NewCipher(key[16:32])
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, key[0:16]).CryptBlocks(plain, data)

	zr, err := zlib.NewReader(bytes.NewReader(plain))
	if err != nil {
		return false, nil // A wrong password almost always dies here.
	}
	defer func() { _ = zr.Close() }()
	out := make([]byte, electrumInflateMax)
	n, err := io.ReadFull(zr, out)
	if n == 0 || (err != nil && err != io.EOF && err != io.ErrUnexpectedEOF) {
		return false, nil
	}
	return electrumLooksLikeWallet(out[:n]), nil
}
