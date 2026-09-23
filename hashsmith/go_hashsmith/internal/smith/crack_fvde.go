package smith

// FileVault 2 and APFS volumes — Hashcat 16700 and 18300.
//
//	$fvde$<version>$<saltlen>$<salt>$<iterations>$<wrapped key>
//
// Both are the same shape: PBKDF2-HMAC-SHA256 over the passphrase and the
// volume's salt, then an RFC 3394 AES key unwrap whose integrity value is the
// standard eight bytes of 0xa6. Version 1 is CoreStorage (FileVault 2) and
// version 2 is APFS, and two things differ between them.
//
// The KEK width: CoreStorage takes the first 16 bytes of the derived key and
// unwraps under AES-128, APFS takes all 32 and uses AES-256. Hashcat expresses
// this by having 16700 borrow mode 16200's kernel (Apple Secure Notes, which
// is AES-128) rather than 18300's, which is the only place that difference is
// written down.
//
// And how much key is wrapped, which is readable from the record rather than
// from the version — a 24-byte blob carries two registers, a 40-byte blob four
// — so the unwrap is driven by the blob length.
//
// This is the plain unwrap, not AxCrypt's: six passes, counter mixed into the
// low-order end of A in big-endian order. crack_axcrypt_wrap.go already has it.

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// aesKeyWrapRounds is RFC 3394's fixed pass count. AxCrypt parameterises this;
// Apple does not.
const aesKeyWrapRounds = 6

type fvdeRecord struct {
	version    int
	salt       []byte
	iterations int
	wrapped    []byte
}

func parseFVDE(target string) (*fvdeRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$fvde$") {
		return nil, errors.New("not a FileVault 2 / APFS record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$fvde$"), "$")
	if len(p) != 5 {
		return nil, errors.New("FileVault record must be $fvde$<version>$<saltlen>$<salt>$<iterations>$<blob>")
	}
	f := &fvdeRecord{}
	var err error
	if f.version, err = strconv.Atoi(p[0]); err != nil || (f.version != 1 && f.version != 2) {
		return nil, errors.New("FileVault record version must be 1 (CoreStorage) or 2 (APFS)")
	}
	saltLen, err := strconv.Atoi(p[1])
	if err != nil || saltLen < 1 {
		return nil, errors.New("FileVault salt length must be a positive integer")
	}
	if f.salt, err = hex.DecodeString(p[2]); err != nil {
		return nil, errors.New("FileVault salt is not hex")
	}
	// The record states the salt length as well as writing it out. Checking
	// them against each other is what stops a truncated record being read as a
	// shorter valid one.
	if len(f.salt) != saltLen {
		return nil, errors.New("FileVault salt length does not match the salt")
	}
	if f.iterations, err = strconv.Atoi(p[3]); err != nil || f.iterations < 1 {
		return nil, errors.New("FileVault iterations must be a positive integer")
	}
	if f.wrapped, err = hex.DecodeString(p[4]); err != nil {
		return nil, errors.New("FileVault wrapped key is not hex")
	}
	// A wrapped key is the 8-byte integrity value followed by whole 8-byte
	// registers, and there has to be at least one of them.
	if len(f.wrapped) < 16 || len(f.wrapped)%8 != 0 {
		return nil, errors.New("FileVault wrapped key must be a whole number of 8-byte blocks")
	}
	return f, nil
}

func verifyFVDE(target, candidate string) (bool, error) {
	f, err := parseFVDE(target)
	if err != nil {
		return false, err
	}
	keyLen := 32
	if f.version == 1 {
		keyLen = 16
	}
	key := pbkdf2.Key([]byte(candidate), f.salt, f.iterations, 32, sha256.New)
	block, err := aes.NewCipher(key[:keyLen])
	if err != nil {
		return false, err
	}
	return axcryptUnwrap(block, f.wrapped, aesKeyWrapRounds, false), nil
}
