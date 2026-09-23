package main

// Oracle's older logon exchanges, captured off the wire.
//
//	$o3logon$<USER>$<session key>$<encrypted password>
//	$o10glogon$<user>$<server key>$<client key>$<encrypted password>
//
// These are the two generations before the $o5logon$ record
// crack_oracle_logon.go reads, and they differ from it in a way worth naming:
// the thing recovered from a correct password is THE PASSWORD ITSELF. Oracle
// encrypts the password under a key derived from the password, so a candidate
// is checked by decrypting and asking whether what came out is the candidate.
// There is no digest anywhere in the record.
//
// The key derivation is the same in both and predates everything else here.
// The username and password are concatenated as UTF-16BE, upper-cased, and
// DES-CBC-encrypted twice: once under the fixed key 0123456789ABCDEF, and then
// again under the last ciphertext block of that first pass. The second pass's
// last block is the key. Oracle has been doing this since version 6 and the
// fixed key has never changed, which is why it can be written here as a
// constant rather than read from anywhere.
//
// What the two generations differ in is what that key then unlocks. The 9i
// exchange wraps a 3DES session key and then the password under it, with two
// fixed entropy strings folded into a SHA-1 along the way. The 10g exchange
// wraps an AES session key at each end, XORs the two halves together and MD5s
// them into the key the password is under — so both the server's and the
// client's contributions are in the record, and either alone is useless.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"
)

const (
	o3logonPrefix   = "$o3logon$"
	o10gLogonPrefix = "$o10glogon$"
)

// oracleFixedDESKey is the key Oracle has folded passwords under since the
// 1980s. It is a constant in every client and server, and its value is the
// first eight bytes of the hexadecimal alphabet.
var oracleFixedDESKey = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

// The two entropy strings the 9i exchange mixes into its key derivations.
var (
	oracleFixed31 = []byte{
		0xA2, 0xFB, 0xE6, 0xAD, 0x4C, 0x7D, 0x1E, 0x3D,
		0x6E, 0xB0, 0xB7, 0x6C, 0x97, 0xEF, 0xFF, 0x84,
		0x44, 0x71, 0x02, 0x84, 0xAC, 0xF1, 0x3B, 0x29,
		0x5C, 0x0F, 0x0C, 0xB1, 0x87, 0x75, 0xEF,
	}
	oracleFixed23 = []byte{
		0xF2, 0xFF, 0x97, 0x87, 0x15, 0x37, 0x07, 0x76,
		0x07, 0x27, 0xE2, 0x7F, 0xA3, 0xB1, 0xD6, 0x73,
		0x3F, 0x2F, 0xD1, 0x52, 0xAB, 0xAC, 0xC0,
	}
	// The 9i 3DES exchange's initialisation vector, which is a constant with
	// a single bit set in each byte.
	oracleTNSIV = []byte{0x80, 0x20, 0x40, 0x04, 0x08, 0x02, 0x10, 0x01}
)

// oracleUTF16Upper renders a string as Oracle does: upper-cased, big-endian
// UTF-16.
func oracleUTF16Upper(s string) []byte {
	units := utf16.Encode([]rune(strings.ToUpper(s)))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return out
}

// oracleLogonKey folds the username and password into the eight bytes every
// Oracle logon exchange is keyed on.
func oracleLogonKey(user, password string) ([]byte, error) {
	buf := append(oracleUTF16Upper(user), oracleUTF16Upper(password)...)
	// CBC over a buffer that need not be a whole number of blocks: the last
	// partial block is encrypted as its own, which is what OpenSSL's ncbc
	// does and what Oracle relies on.
	cbcLast := func(key, data []byte) ([]byte, error) {
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, des.BlockSize)
		var in [des.BlockSize]byte
		for off := 0; off < len(data); off += des.BlockSize {
			for i := range in {
				in[i] = 0
				if off+i < len(data) {
					in[i] = data[off+i]
				}
				in[i] ^= iv[i]
			}
			out := make([]byte, des.BlockSize)
			block.Encrypt(out, in[:])
			iv = out
		}
		return iv, nil
	}
	first, err := cbcLast(oracleFixedDESKey, buf)
	if err != nil {
		return nil, err
	}
	return cbcLast(first, buf)
}

// oracleTNSKeySHA1 builds a 24-byte 3DES key from an input and one of the
// fixed entropy strings. The second half is seeded with NINETEEN bytes of the
// first — its last nineteen, not its first — which is the sort of detail that
// only a reference implementation records.
func oracleTNSKeySHA1(input, entropy []byte) []byte {
	out := make([]byte, 40)
	h := sha1.New()
	_, _ = h.Write(input)
	_, _ = h.Write(entropy)
	copy(out, h.Sum(nil))
	h.Reset()
	_, _ = h.Write(input)
	_, _ = h.Write([]byte{2})
	_, _ = h.Write(out[1:20])
	_, _ = h.Write(entropy)
	copy(out[20:], h.Sum(nil))
	return out[:24]
}

func oracle3DESDecrypt(key, in, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(in)/des.BlockSize*des.BlockSize)
	if len(out) == 0 {
		return nil, errors.New("nothing to decrypt")
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, in[:len(out)])
	return out, nil
}

func oracleAES128Decrypt(key, in []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(in)/aes.BlockSize*aes.BlockSize)
	if len(out) == 0 {
		return nil, errors.New("nothing to decrypt")
	}
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, in[:len(out)])
	return out, nil
}

// ── Oracle 9i ─────────────────────────────────────────────────────────────────

func o3logonFields(target string) (user string, sessKey, authPass []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, o3logonPrefix) {
		return "", nil, nil, errors.New("not an Oracle 9i logon record")
	}
	f := strings.Split(t[len(o3logonPrefix):], "$")
	if len(f) != 3 || f[0] == "" {
		return "", nil, nil, errors.New("an $o3logon$ record is <user>$<session key>$<password>")
	}
	if sessKey, err = decodeExactHex(f[1], 16, "Oracle session key"); err != nil {
		return "", nil, nil, err
	}
	if authPass, err = hex.DecodeString(f[2]); err != nil || len(authPass) < 8 || len(authPass)%8 != 0 {
		return "", nil, nil, errors.New("an Oracle 9i encrypted password is a whole number of DES blocks")
	}
	return f[0], sessKey, authPass, nil
}

func verifyO3Logon(target, candidate string) (bool, error) {
	user, sessKey, authPass, err := o3logonFields(target)
	if err != nil {
		return false, err
	}
	hash, err := oracleLogonKey(user, candidate)
	if err != nil {
		return false, err
	}
	sess, err := oracle3DESDecrypt(oracleTNSKeySHA1(hash, oracleFixed31), sessKey, oracleTNSIV)
	if err != nil {
		return false, err
	}
	obf, err := oracle3DESDecrypt(oracleTNSKeySHA1(sess, oracleFixed23), authPass, oracleTNSIV)
	if err != nil {
		return false, err
	}
	// The plaintext is rotated: the last four bytes come first, then
	// everything from the fourth onwards.
	n := len(obf)
	plain := make([]byte, 0, n)
	plain = append(plain, obf[n-4:]...)
	plain = append(plain, obf[4:]...)
	return len(plain) >= len(candidate) && string(plain[:len(candidate)]) == candidate, nil
}

func isO3Logon(target string) bool {
	_, _, _, err := o3logonFields(target)
	return err == nil
}

// ── Oracle 10g ────────────────────────────────────────────────────────────────

func o10gLogonFields(target string) (user string, serverKey, clientKey, authPass []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, o10gLogonPrefix) {
		return "", nil, nil, nil, errors.New("not an Oracle 10g logon record")
	}
	f := strings.Split(t[len(o10gLogonPrefix):], "$")
	if len(f) != 4 || f[0] == "" {
		return "", nil, nil, nil, errors.New("an $o10glogon$ record is <user>$<server key>$<client key>$<password>")
	}
	if serverKey, err = decodeExactHex(f[1], 32, "Oracle server session key"); err != nil {
		return "", nil, nil, nil, err
	}
	if clientKey, err = decodeExactHex(f[2], 32, "Oracle client session key"); err != nil {
		return "", nil, nil, nil, err
	}
	if authPass, err = hex.DecodeString(f[3]); err != nil || len(authPass) < 32 || len(authPass)%16 != 0 {
		return "", nil, nil, nil, errors.New("an Oracle 10g encrypted password is at least two AES blocks")
	}
	return f[0], serverKey, clientKey, authPass, nil
}

func verifyO10gLogon(target, candidate string) (bool, error) {
	user, serverKey, clientKey, authPass, err := o10gLogonFields(target)
	if err != nil {
		return false, err
	}
	hash, err := oracleLogonKey(user, candidate)
	if err != nil {
		return false, err
	}
	// The eight bytes of the fold become a 128-bit AES key by zero padding,
	// so half the key is known to everyone.
	aesKey := make([]byte, 16)
	copy(aesKey, hash)

	server, err := oracleAES128Decrypt(aesKey, serverKey)
	if err != nil {
		return false, err
	}
	client, err := oracleAES128Decrypt(aesKey, clientKey)
	if err != nil {
		return false, err
	}
	combined := make([]byte, 16)
	for i := range combined {
		combined[i] = server[16+i] ^ client[16+i]
	}
	sum := md5.Sum(combined)

	plain, err := oracleAES128Decrypt(sum[:], authPass)
	if err != nil {
		return false, err
	}
	// The first block is discarded — it is the salt the client prefixed —
	// and what follows is the password padded with a repeated byte.
	body := plain[16:]
	n := 0
	for n < len(body) && body[n] >= 32 && body[n] <= 126 {
		n++
	}
	if n == 0 || n >= len(body) {
		return false, nil
	}
	padding := body[n]
	for i := n; i < len(body); i++ {
		if body[i] != padding {
			return false, nil
		}
	}
	return string(body[:n]) == candidate, nil
}

func isO10gLogon(target string) bool {
	_, _, _, _, err := o10gLogonFields(target)
	return err == nil
}
