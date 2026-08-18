package main

// Assorted network-device and service password formats.
//
//	1<salt><sha1>              Citrix NetScaler — sha1(salt . pass . "\x00")
//	<pix16>                    Cisco-PIX  — md5(pad16(pass)), PIX-base64
//	<pix16>:<salt>             Cisco-ASA  — md5(pad16(pass . salt)), PIX-base64
//	$cram_md5$<chal>$<resp>    CRAM-MD5   — HMAC-MD5(pass, challenge)
//	SCRAM-SHA-256$i:salt$sk:srv  PostgreSQL SCRAM — PBKDF2 + HMAC/SHA-256

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ── Citrix NetScaler ──

func verifyCitrix(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 49 || targetHash[0] != '1' {
		return false, errors.New("invalid NetScaler hash (need 1 + 8-char salt + 40-char sha1)")
	}
	salt := targetHash[1:9]
	want := targetHash[9:]
	h := sha1.New()
	h.Write([]byte(salt))
	h.Write([]byte(candidate))
	h.Write([]byte{0})
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want), nil
}

func isCitrix(s string) bool {
	return len(s) == 49 && s[0] == '1' && isHex(s[9:]) && isHex(s[1:9])
}

// ── Cisco PIX / ASA ──

// pixEncode md5-selects bytes [0,1,2,4,5,6,8,9,10,12,13,14] and crypt-base64s
// them (LSB-first), producing 16 characters.
func pixEncode(digest []byte) string {
	sel := []byte{
		digest[0], digest[1], digest[2], digest[4], digest[5], digest[6],
		digest[8], digest[9], digest[10], digest[12], digest[13], digest[14],
	}
	var out strings.Builder
	for i := 0; i < 12; i += 3 {
		g := uint32(sel[i]) | uint32(sel[i+1])<<8 | uint32(sel[i+2])<<16
		for k := 0; k < 4; k++ {
			out.WriteByte(itoa64[(g>>(6*uint(k)))&0x3f])
		}
	}
	return out.String()
}

// pad16 zero-pads or truncates a byte slice to exactly 16 bytes.
func pad16(b []byte) []byte {
	out := make([]byte, 16)
	copy(out, b)
	return out
}

func verifyCiscoPIX(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 16 {
		return false, errors.New("invalid Cisco-PIX hash (need 16 chars)")
	}
	d := md5.Sum(pad16([]byte(candidate)))
	return pixEncode(d[:]) == targetHash, nil
}

func verifyCiscoASA(targetHash, candidate string) (bool, error) {
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[0]) != 16 {
		return false, errors.New("invalid Cisco-ASA hash (need pix:salt)")
	}
	d := md5.Sum(pad16(append([]byte(candidate), f[1]...)))
	return pixEncode(d[:]) == f[0], nil
}

func isCiscoASA(s string) bool {
	f := strings.SplitN(s, ":", 2)
	return len(f) == 2 && len(f[0]) == 16 && f[1] != "" && isPixToken(f[0])
}

func isPixToken(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(itoa64, s[i]) < 0 {
			return false
		}
	}
	return true
}

// ── CRAM-MD5 ──

func verifyCRAMMD5(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$cram_md5$") {
		return false, errors.New("invalid CRAM-MD5 hash (missing $cram_md5$ prefix)")
	}
	f := strings.Split(targetHash[len("$cram_md5$"):], "$")
	if len(f) != 2 {
		return false, errors.New("invalid CRAM-MD5 hash (need challenge$response)")
	}
	challenge, err := base64.StdEncoding.DecodeString(f[0])
	if err != nil {
		return false, errors.New("invalid CRAM-MD5 challenge")
	}
	resp, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return false, errors.New("invalid CRAM-MD5 response")
	}
	// response is "username <hex-hmac>"; take the last whitespace-separated field.
	parts := strings.Fields(string(resp))
	if len(parts) == 0 {
		return false, errors.New("invalid CRAM-MD5 response body")
	}
	want := parts[len(parts)-1]
	mac := hmac.New(md5.New, []byte(candidate))
	mac.Write(challenge)
	return strings.EqualFold(hex.EncodeToString(mac.Sum(nil)), want), nil
}

// ── PostgreSQL SCRAM-SHA-256 ──

func verifySCRAM(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "SCRAM-SHA-256$") {
		return false, errors.New("invalid SCRAM hash (missing SCRAM-SHA-256$ prefix)")
	}
	body := targetHash[len("SCRAM-SHA-256$"):]
	dollar := strings.IndexByte(body, '$')
	if dollar < 0 {
		return false, errors.New("invalid SCRAM hash (missing key section)")
	}
	iterSalt := strings.SplitN(body[:dollar], ":", 2)
	if len(iterSalt) != 2 {
		return false, errors.New("invalid SCRAM iter:salt")
	}
	iter, err := strconv.Atoi(iterSalt[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid SCRAM iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(iterSalt[1])
	if err != nil {
		return false, errors.New("invalid SCRAM salt")
	}
	keys := strings.SplitN(body[dollar+1:], ":", 2)
	if len(keys) != 2 {
		return false, errors.New("invalid SCRAM stored:server keys")
	}
	storedKey, err := base64.StdEncoding.DecodeString(keys[0])
	if err != nil || len(storedKey) != 32 {
		return false, errors.New("invalid SCRAM stored key")
	}
	saltedPassword := pbkdf2.Key([]byte(candidate), salt, iter, 32, sha256.New)
	ck := hmac.New(sha256.New, saltedPassword)
	ck.Write([]byte("Client Key"))
	clientKey := ck.Sum(nil)
	got := sha256.Sum256(clientKey)
	return bytesEqualCT(got[:], storedKey), nil
}
