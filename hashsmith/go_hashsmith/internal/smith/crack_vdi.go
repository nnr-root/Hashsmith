package smith

// VirtualBox disk encryption.
//
//	$vdi$<cipher>$<hash>$<key iterations>$<final iterations>$<key length>$
//	     <digest length>$<key salt>$<final salt>$<encrypted key>$<final hash>
//
// VirtualBox does not protect the disk with the password. It protects a data
// encryption key with it, and stores a second hash of that key so the GUI can
// say "wrong password" without decrypting anything. That second hash is what
// makes the record checkable, and it is why the check runs two derivations
// rather than one:
//
//	key   = PBKDF2(password, key salt, key iterations)
//	DEK   = AES-XTS decrypt(encrypted key, key)
//	check = PBKDF2(DEK, final salt, final iterations) == final hash
//
// The cost is therefore both iteration counts, not one — which is worth
// knowing before starting a run against a disk image.

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

const vdiPrefix = "$vdi$"

type vdiRecord struct {
	newHash          func() hash.Hash
	keyIter, endIter int
	keyLen           int
	keySalt, endSalt []byte
	encKey, want     []byte
}

func parseVDI(target string) (*vdiRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, vdiPrefix) {
		return nil, errors.New("not a VirtualBox disk record")
	}
	f := strings.Split(t[len(vdiPrefix):], "$")
	if len(f) != 10 {
		return nil, errors.New("a VirtualBox disk record has ten fields")
	}
	// The cipher field names the key width as well as the mode; only the
	// XTS variants exist, and the key length is stated separately anyway.
	if !strings.HasPrefix(f[0], "aes-xts") {
		return nil, errors.New("unsupported VirtualBox cipher " + f[0])
	}
	r := &vdiRecord{}
	switch f[1] {
	case "sha256":
		r.newHash = sha256.New
	case "sha512":
		r.newHash = sha512.New
	case "sha1":
		return nil, errors.New("unsupported VirtualBox digest " + f[1])
	default:
		return nil, errors.New("unsupported VirtualBox digest " + f[1])
	}
	var err error
	if r.keyIter, err = strconv.Atoi(f[2]); err != nil || r.keyIter < 1 || r.keyIter > maxKDFIterations {
		return nil, errors.New("invalid VirtualBox key iteration count")
	}
	if r.endIter, err = strconv.Atoi(f[3]); err != nil || r.endIter < 1 || r.endIter > maxKDFIterations {
		return nil, errors.New("invalid VirtualBox final iteration count")
	}
	if r.keyLen, err = strconv.Atoi(f[4]); err != nil || (r.keyLen != 32 && r.keyLen != 64) {
		return nil, errors.New("invalid VirtualBox key length")
	}
	digestLen, err := strconv.Atoi(f[5])
	if err != nil || digestLen < 1 || digestLen > 64 {
		return nil, errors.New("invalid VirtualBox digest length")
	}
	for _, x := range []struct {
		dst  *[]byte
		text string
		name string
	}{
		{&r.keySalt, f[6], "key salt"},
		{&r.endSalt, f[7], "final salt"},
		{&r.encKey, f[8], "encrypted key"},
		{&r.want, f[9], "final hash"},
	} {
		if *x.dst, err = hex.DecodeString(x.text); err != nil || len(*x.dst) == 0 {
			return nil, errors.New("invalid VirtualBox " + x.name)
		}
	}
	if len(r.encKey) != r.keyLen || len(r.want) != digestLen {
		return nil, errors.New("VirtualBox field lengths disagree with the header")
	}
	return r, nil
}

// verifyVDI checks a VirtualBox-encrypted disk image.
func verifyVDI(target, candidate string) (bool, error) {
	r, err := parseVDI(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), r.keySalt, r.keyIter, r.keyLen, r.newHash)
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return false, err
	}
	dek := make([]byte, len(r.encKey))
	c.Decrypt(dek, r.encKey, 0)
	got := pbkdf2.Key(dek, r.endSalt, r.endIter, len(r.want), r.newHash)
	return hmac.Equal(got, r.want), nil
}

func isVDI(target string) bool {
	_, err := parseVDI(target)
	return err == nil
}
