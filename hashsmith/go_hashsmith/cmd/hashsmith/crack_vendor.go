package main

// Vendor and platform password formats that are a thin wrapper over primitives
// Hashsmith already implements.  Each one is a documented construction plus a
// distinctive ciphertext encoding, so the work here is parsing the record and
// feeding the right bytes to an existing digest or KDF.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// ── PeopleSoft ────────────────────────────────────────────────────────────────

// verifyPeopleSoft checks a PeopleSoft PS_TOKEN password (Hashcat 133):
//
//	base64(sha1(utf16le($pass)))
//
// The record is the bare base64 digest, with no salt and no iteration count.
func verifyPeopleSoft(targetHash, candidate string) (bool, error) {
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(targetHash))
	if err != nil || len(want) != sha1.Size {
		return false, errors.New("invalid PeopleSoft hash (need base64 of a 20-byte SHA-1)")
	}
	sum := sha1.Sum(utf16le(candidate))
	return bytesEqualCT(sum[:], want), nil
}

func isPeopleSoft(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 28 || !strings.HasSuffix(s, "=") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == sha1.Size
}

// ── Episerver ─────────────────────────────────────────────────────────────────

// verifyEpiserver checks an Episerver CMS password (Hashcat 141 and 1441):
//
//	version 0: base64(sha1($salt . utf16le($pass)))     — Episerver 6.x < .NET 4
//	version 1: base64(sha256($salt . utf16le($pass)))   — Episerver 6.x >= .NET 4
//
// Record: $episerver$*<version>*<base64 salt>*<base64 digest>.  The salt is the
// decoded base64 used as raw bytes, not its textual form.
func verifyEpiserver(targetHash, candidate string) (bool, error) {
	version, salt, want, err := parseEpiserver(targetHash)
	if err != nil {
		return false, err
	}
	var got []byte
	if version == 0 {
		sum := sha1.Sum(append(salt, utf16le(candidate)...))
		got = sum[:]
	} else {
		sum := sha256.Sum256(append(salt, utf16le(candidate)...))
		got = sum[:]
	}
	return bytesEqualCT(got, want), nil
}

func parseEpiserver(target string) (version int, salt, digest []byte, err error) {
	if !strings.HasPrefix(target, "$episerver$*") {
		return 0, nil, nil, errors.New("invalid Episerver hash (missing $episerver$ prefix)")
	}
	f := strings.Split(target[len("$episerver$*"):], "*")
	if len(f) != 3 {
		return 0, nil, nil, errors.New("invalid Episerver hash (need version*salt*digest)")
	}
	version, err = strconv.Atoi(f[0])
	if err != nil || (version != 0 && version != 1) {
		return 0, nil, nil, errors.New("unsupported Episerver version (need 0 or 1)")
	}
	if salt, err = base64.StdEncoding.DecodeString(f[1]); err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return 0, nil, nil, errors.New("invalid Episerver salt")
	}
	if digest, err = base64.StdEncoding.DecodeString(f[2]); err != nil {
		return 0, nil, nil, errors.New("invalid Episerver digest")
	}
	wantLen := sha1.Size
	if version == 1 {
		wantLen = sha256.Size
	}
	if len(digest) != wantLen {
		return 0, nil, nil, errors.New("Episerver digest length does not match the version")
	}
	return version, salt, digest, nil
}

func isEpiserver(s string) bool {
	_, _, _, err := parseEpiserver(s)
	return err == nil
}

// ── MS-AzureSync / Azure AD Connect ───────────────────────────────────────────

// verifyAzureSync checks an MS-AzureSync password blob (Hashcat 12800):
//
//	PBKDF2-HMAC-SHA256(MD4(utf16le($pass)), $salt, $iter, 32)
//
// The PBKDF2 password is the raw 16-byte NT hash, which is why an attacker who
// already holds the NT hash does not need the cleartext at all.
//
// Record: v1;PPH1_MD4,<hex salt>,<iterations>,<hex digest>
func verifyAzureSync(targetHash, candidate string) (bool, error) {
	salt, iter, want, err := parseAzureSync(targetHash)
	if err != nil {
		return false, err
	}
	nt := md4.New()
	_, _ = nt.Write(utf16le(candidate))
	got := pbkdf2.Key(nt.Sum(nil), salt, iter, len(want), sha256.New)
	return bytesEqualCT(got, want), nil
}

func parseAzureSync(target string) (salt []byte, iter int, digest []byte, err error) {
	const prefix = "v1;PPH1_MD4,"
	if !strings.HasPrefix(target, prefix) {
		return nil, 0, nil, errors.New("invalid MS-AzureSync hash (missing v1;PPH1_MD4, prefix)")
	}
	f := strings.Split(target[len(prefix):], ",")
	if len(f) != 3 {
		return nil, 0, nil, errors.New("invalid MS-AzureSync hash (need salt,iterations,digest)")
	}
	if salt, err = hex.DecodeString(f[0]); err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return nil, 0, nil, errors.New("invalid MS-AzureSync salt")
	}
	if iter, err = strconv.Atoi(f[1]); err != nil || iter < 1 || iter > maxKDFIterations {
		return nil, 0, nil, errors.New("invalid MS-AzureSync iteration count")
	}
	if digest, err = hex.DecodeString(f[2]); err != nil || len(digest) == 0 || len(digest) > maxKDFFieldSize {
		return nil, 0, nil, errors.New("invalid MS-AzureSync digest")
	}
	return salt, iter, digest, nil
}

func isAzureSync(s string) bool {
	_, _, _, err := parseAzureSync(s)
	return err == nil
}

// ── hMailServer ───────────────────────────────────────────────────────────────

// verifyHMailServer checks an hMailServer password (Hashcat 1421):
//
//	sha256($salt . $pass)
//
// The record is unusual in that the six-character salt is not a separate field
// — it is simply the first six characters of the stored string, with the
// SHA-256 hex digest following it.
func verifyHMailServer(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 6+64 || !isHex(targetHash[6:]) {
		return false, errors.New("invalid hMailServer hash (need a 6-char salt then 64 hex chars)")
	}
	sum := sha256.Sum256([]byte(targetHash[:6] + candidate))
	return strings.EqualFold(hex.EncodeToString(sum[:]), targetHash[6:]), nil
}

func isHMailServer(s string) bool {
	return len(s) == 70 && isHex(s[6:]) && !isHex(s[:6])
}
