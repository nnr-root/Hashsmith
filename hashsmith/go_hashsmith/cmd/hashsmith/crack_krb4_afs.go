package main

// Kerberos 4 and AFS: the string-to-key functions that predate everything.
//
//	$af$<realm>$<32 hex>    a captured Kerberos 4 TGT fragment
//	$K4$<8 hex>,<cell>      an AFS key from the KeyFile
//
// AFS's string-to-key is two functions with a length test between them, and
// the test is on the PASSWORD: eight characters or fewer take one path, nine
// or more the other. That is not a tuning choice, it is the seam between two
// implementations — CMU's original, which ran the password through crypt(3)
// and therefore could never use more than eight characters of it, and
// Transarc's replacement, which fixed that by hashing the whole thing with DES
// in CBC. Both are still live, because a cell full of short passwords is
// still using the first.
//
// The CMU path is worth looking at twice. It XORs the password with the cell
// name, replaces any resulting NUL with 'X', hands the eight bytes to crypt(3)
// under the fixed salt "p1", takes eight characters of the output, and shifts
// each left by one bit to make room for DES's parity. A password of more than
// eight characters loses everything past the eighth, and a cell name longer
// than the password contributes its own bytes to the key.

import (
	"crypto/des"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	krb4Prefix = "$af$"
	afsPrefix  = "$K4$"
	// Kerberos 4's realm field, which the key derivation truncates to.
	krb4RealmSize = 40
)

// desSetOddParity sets the low bit of each byte so the byte has odd parity,
// which is what DES hardware expected and what every one of these functions
// does to its result.
func desSetOddParity(key []byte) {
	for i, b := range key {
		v := b & 0xFE
		ones := 0
		for j := 1; j < 8; j++ {
			if v&(1<<uint(j)) != 0 {
				ones++
			}
		}
		if ones%2 == 0 {
			v |= 1
		}
		key[i] = v
	}
}

// desCBCChecksum is OpenSSL's DES_cbc_cksum: CBC-encrypt the data and keep
// only the last block. The data is padded with zeros to a whole block.
func desCBCChecksum(data, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	copy(out, iv)
	var buf [8]byte
	for off := 0; off < len(data); off += 8 {
		for i := range buf {
			buf[i] = 0
			if off+i < len(data) {
				buf[i] = data[off+i]
			}
			buf[i] ^= out[i]
		}
		block.Encrypt(out, buf[:])
	}
	return out, nil
}

// afsStringToKey derives the DES key AFS stores.
func afsStringToKey(password, cell string) ([]byte, error) {
	realm := strings.ToLower(cell)
	if len(realm) > krb4RealmSize {
		realm = realm[:krb4RealmSize]
	}
	if len(password) > 8 {
		return afsTransarcStringToKey(password, realm)
	}
	return afsCMUStringToKey(password, realm)
}

// afsCMUStringToKey is the crypt(3) path, for passwords of eight bytes or
// fewer.
func afsCMUStringToKey(password, cell string) ([]byte, error) {
	var buf [8]byte
	copy(buf[:], cell)
	n := len(password)
	if n > 8 {
		n = 8
	}
	for i := 0; i < n; i++ {
		var c byte
		if i < len(cell) {
			c = cell[i]
		}
		buf[i] = password[i] ^ c
	}
	for i := range buf {
		if buf[i] == 0 {
			buf[i] = 'X'
		}
	}
	crypted, err := descryptRaw(string(buf[:]), "p1")
	if err != nil {
		return nil, err
	}
	// crypt(3) returns the two salt characters followed by eleven of output;
	// eight of those eleven become the key.
	if len(crypted) < 2+8 {
		return nil, errors.New("crypt(3) returned too little for an AFS key")
	}
	key := []byte(crypted[2 : 2+8])
	for i := range key {
		key[i] <<= 1
	}
	desSetOddParity(key)
	return key, nil
}

// afsTransarcStringToKey is the DES path, for longer passwords.
func afsTransarcStringToKey(password, cell string) ([]byte, error) {
	data := []byte(password + cell)
	if len(data) > 512 {
		data = data[:512]
	}
	temp := []byte("kerberos")
	desSetOddParity(temp)
	iv, err := desCBCChecksum(data, temp, []byte("kerberos"))
	if err != nil {
		return nil, err
	}
	temp = append([]byte(nil), iv...)
	desSetOddParity(temp)
	key, err := desCBCChecksum(data, temp, iv)
	if err != nil {
		return nil, err
	}
	desSetOddParity(key)
	return key, nil
}

// desPCBCDecrypt is DES in propagating CBC, which Kerberos 4 used and almost
// nothing since has. Each block's feedback is the XOR of the plaintext and
// ciphertext that preceded it rather than the ciphertext alone, so a single
// corrupted block ruins everything after it — which is the property Kerberos
// wanted and the reason the trailing "krbtgt" is worth checking.
func desPCBCDecrypt(ct, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	feedback := append([]byte(nil), key...)
	var tmp [8]byte
	for off := 0; off+8 <= len(ct); off += 8 {
		block.Decrypt(tmp[:], ct[off:off+8])
		for i := 0; i < 8; i++ {
			out[off+i] = tmp[i] ^ feedback[i]
			feedback[i] = out[off+i] ^ ct[off+i]
		}
	}
	return out, nil
}

func krb4Fields(target string) (realm string, tgt []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, krb4Prefix) {
		return "", nil, errors.New("not a Kerberos 4 record")
	}
	realm, digest, ok := strings.Cut(t[len(krb4Prefix):], "$")
	if !ok || realm == "" || strings.Contains(digest, "$") {
		return "", nil, errors.New("a Kerberos 4 record is $af$<realm>$<ticket>")
	}
	if tgt, err = decodeExactHex(digest, 16, "Kerberos 4 ticket"); err != nil {
		return "", nil, err
	}
	return realm, tgt, nil
}

// verifyKRB4 checks a captured ticket fragment. There is no digest to compare:
// the ticket is decrypted and the answer is whether the word "krbtgt" appears
// where the ticket says it should.
func verifyKRB4(target, candidate string) (bool, error) {
	realm, tgt, err := krb4Fields(target)
	if err != nil {
		return false, err
	}
	key, err := afsStringToKey(candidate, realm)
	if err != nil {
		return false, err
	}
	plain, err := desPCBCDecrypt(tgt, key)
	if err != nil {
		return false, err
	}
	return string(plain[8:14]) == "krbtgt", nil
}

func isKRB4(target string) bool {
	_, _, err := krb4Fields(target)
	return err == nil
}

// ── AFS KeyFile ───────────────────────────────────────────────────────────────

// "$K4$<8 hex>,<cell>" — the derived key itself, which is what an AFS KeyFile
// holds. Nothing is encrypted and nothing is compared but the key.
func afsFields(target string) (key []byte, cell string, err error) {
	t := strings.TrimSpace(target)
	if len(t) < len(afsPrefix) || !strings.EqualFold(t[:len(afsPrefix)], afsPrefix) {
		return nil, "", errors.New("not an AFS record")
	}
	digest, cell, ok := strings.Cut(t[len(afsPrefix):], ",")
	if !ok {
		return nil, "", errors.New("an AFS record is $K4$<key>,<cell>")
	}
	if key, err = decodeExactHex(digest, 8, "AFS key"); err != nil {
		return nil, "", err
	}
	return key, cell, nil
}

func verifyAFS(target, candidate string) (bool, error) {
	want, cell, err := afsFields(target)
	if err != nil {
		return false, err
	}
	got, err := afsStringToKey(candidate, cell)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(got) == hex.EncodeToString(want), nil
}

func isAFS(target string) bool {
	_, _, err := afsFields(target)
	return err == nil
}
