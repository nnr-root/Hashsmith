package main

// Oracle's logon exchange, captured off the wire.
//
//	$o5logon$<AUTH_SESSKEY>*<AUTH_VFR_DATA>
//
// Oracle 11g's authentication sends the server's session key encrypted under
// a key derived from the password, together with the salt it was derived
// with. Both travel in the clear in the first exchange, so anyone watching a
// login can collect the pair — no access to the database, and nothing stored
// on disk.
//
// The derivation is deliberately thin: SHA-1 over the password and the salt,
// zero-extended from twenty bytes to twenty-four because AES has no 160-bit
// key. What makes a guess checkable is the padding: the plaintext session key
// is 40 bytes padded to 48, so a correct key leaves eight bytes of 0x08 at
// the end and a wrong one leaves eight random bytes.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

const oracleLogonPrefix = "$o5logon$"

// oracleLogonFields reads the session key and the salt.
func oracleLogonFields(target string) (sessKey, salt []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, oracleLogonPrefix) {
		return nil, nil, errors.New("not an Oracle o5logon record")
	}
	// The two fields are separated by '*', and some extractors write a
	// username and a '$' before them.
	body := t[len(oracleLogonPrefix):]
	if i := strings.LastIndexByte(body, '$'); i >= 0 {
		body = body[i+1:]
	}
	f := strings.Split(body, "*")
	if len(f) != 2 {
		return nil, nil, errors.New("an o5logon record is <session key>*<salt>")
	}
	if sessKey, err = hex.DecodeString(f[0]); err != nil ||
		len(sessKey) == 0 || len(sessKey)%aes.BlockSize != 0 {
		return nil, nil, errors.New("invalid o5logon session key")
	}
	if salt, err = hex.DecodeString(f[1]); err != nil || len(salt) == 0 || len(salt) > 64 {
		return nil, nil, errors.New("invalid o5logon salt")
	}
	return sessKey, salt, nil
}

// verifyOracleLogon checks a captured Oracle 11g logon.
func verifyOracleLogon(target, candidate string) (bool, error) {
	sessKey, salt, err := oracleLogonFields(target)
	if err != nil {
		return false, err
	}
	sum := sha1.Sum(append([]byte(candidate), salt...))
	// AES has no 160-bit key, so the twenty bytes SHA-1 produces are
	// zero-extended to a 192-bit one.
	key := make([]byte, 24)
	copy(key, sum[:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(sessKey))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, sessKey)
	// Forty bytes of session key padded to forty-eight: the last eight are
	// 0x08 when the key was right, and random when it was not.
	tail := plain[len(plain)-8:]
	for _, b := range tail {
		if b != 0x08 {
			return false, nil
		}
	}
	return true, nil
}

func isOracleLogon(target string) bool {
	_, _, err := oracleLogonFields(target)
	return err == nil
}
