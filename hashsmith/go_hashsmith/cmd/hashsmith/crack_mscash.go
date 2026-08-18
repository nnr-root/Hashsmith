package main

// Domain Cached Credentials (MS Cache):
//
//	DCC  (mscash)  : <md4>:<username>
//	   dcc = md4( md4(utf16le(pass)) . utf16le(lower(user)) )
//	DCC2 (mscash2) : $DCC2$<iter>#<username>#<hash>
//	   dcc2 = PBKDF2-HMAC-SHA1(dcc, utf16le(lower(user)), iter, 16)

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// dccKey computes the DCC (mscash) value for a password and username.
func dccKey(password, username string) []byte {
	nt := md4.New()
	nt.Write(utf16le(password))
	ntHash := nt.Sum(nil)

	d := md4.New()
	d.Write(ntHash)
	d.Write(utf16le(strings.ToLower(username)))
	return d.Sum(nil)
}

// verifyDCC checks a candidate against a <md4>:<username> DCC hash.
func verifyDCC(targetHash, candidate string) (bool, error) {
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[0]) != 32 {
		return false, errors.New("invalid DCC hash (need md4:username)")
	}
	got := hex.EncodeToString(dccKey(candidate, f[1]))
	return strings.EqualFold(got, f[0]), nil
}

// verifyDCC2 checks a candidate against a $DCC2$iter#user#hash hash.
func verifyDCC2(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$DCC2$") {
		return false, errors.New("invalid DCC2 hash (missing $DCC2$ prefix)")
	}
	f := strings.Split(targetHash[len("$DCC2$"):], "#")
	if len(f) != 3 {
		return false, errors.New("invalid DCC2 hash (need iter#user#hash)")
	}
	iter, err := strconv.Atoi(f[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid DCC2 iteration count")
	}
	want, err := hex.DecodeString(f[2])
	if err != nil || len(want) != 16 {
		return false, errors.New("invalid DCC2 digest")
	}
	dcc := dccKey(candidate, f[1])
	got := pbkdf2.Key(dcc, utf16le(strings.ToLower(f[1])), iter, 16, sha1.New)
	return bytesEqualCT(got, want), nil
}

// isDCC2 detects the $DCC2$ format. (Bare DCC shares the <md5>:<salt> shape with
// vBulletin, so detection offers both candidates there.)
func isDCC2(s string) bool { return strings.HasPrefix(s, "$DCC2$") }
