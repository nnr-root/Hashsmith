package main

// Additional compact Hashcat/John records whose full verifier inputs fit in a
// single text line. Implementations follow Hashcat's published test modules.

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func md5HexString(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func verifyDualSaltMD5(target, candidate, variant string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 3 || len(parts[0]) != 32 || !isHex(parts[0]) {
		return false, errors.New("invalid dual-salt MD5 record")
	}
	digest, salt1, salt2 := parts[0], parts[1], parts[2]
	var got string
	switch variant {
	case "upper-inner":
		got = md5HexString(salt1 + strings.ToUpper(md5HexString(salt2+candidate)))
	case "triple":
		got = md5HexString(md5HexString(md5HexString(candidate)+salt1) + salt2)
	case "empirecms":
		inner := md5HexString(md5HexString(candidate) + salt1)
		got = md5HexString(salt2 + "E!m^p-i(r#e.C:M?S" + inner + "d)i.g^o-d" + salt1)
	default:
		return false, errors.New("unknown dual-salt MD5 variant")
	}
	return strings.EqualFold(got, digest), nil
}

func verifyCiscoISE(target, candidate string) (bool, error) {
	if len(target) != 128 || !isHex(target) {
		return false, errors.New("invalid Cisco ISE SHA-256 record")
	}
	salt, err := hex.DecodeString(target[64:])
	if err != nil {
		return false, err
	}
	first := sha256.Sum256(append(append([]byte{}, salt...), []byte(candidate)...))
	digest := first[:]
	for i := 0; i < 128; i++ {
		next := sha256.Sum256(digest)
		digest = next[:]
	}
	return strings.EqualFold(hex.EncodeToString(digest), target[:64]), nil
}

var fortiGateMagic = []byte{
	0xa3, 0x88, 0xba, 0x2e, 0x42, 0x4c, 0xb0, 0x4a,
	0x53, 0x79, 0x30, 0xc1, 0x31, 0x07, 0xcc, 0x3f,
	0xa1, 0x32, 0x90, 0x29, 0xa9, 0x81, 0x5b, 0x70,
}

func verifyFortiGate(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "AK1") {
		return false, errors.New("invalid FortiGate record")
	}
	decoded, err := base64.StdEncoding.DecodeString(target[3:])
	if err != nil || len(decoded) != 32 {
		return false, errors.New("invalid FortiGate payload")
	}
	salt, want := decoded[:12], decoded[12:]
	h := sha1.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write(fortiGateMagic)
	return bytesEqualCT(h.Sum(nil), want), nil
}

func verifyLastPass(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 4 || len(parts[0]) != 32 || !isHex(parts[0]) || len(parts[3]) != 32 || !isHex(parts[3]) {
		return false, errors.New("invalid LastPass record")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid LastPass iteration count")
	}
	if len(parts[2]) < aes.BlockSize || len(parts[2]) > maxKDFFieldSize {
		return false, errors.New("invalid LastPass account salt")
	}
	want, _ := hex.DecodeString(parts[0])
	iv, _ := hex.DecodeString(parts[3])
	key := pbkdf2.Key([]byte(candidate), []byte(parts[2]), iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := []byte(parts[2])[:aes.BlockSize]
	xored := make([]byte, aes.BlockSize)
	for i := range xored {
		xored[i] = plain[i] ^ iv[i]
	}
	got := make([]byte, aes.BlockSize)
	block.Encrypt(got, xored)
	return bytesEqualCT(got, want), nil
}

func verifySAPIsSHA512(target, candidate string) (bool, error) {
	return verifySAPIteratedSHA(target, candidate, "sha512")
}

func verifyRadmin2(target, candidate string) (bool, error) {
	if len(target) != 32 || !isHex(target) || len([]byte(candidate)) > 100 {
		return false, errors.New("invalid Radmin2 record or password length")
	}
	padded := make([]byte, 100)
	copy(padded, []byte(candidate))
	sum := md5.Sum(padded)
	return strings.EqualFold(hex.EncodeToString(sum[:]), target), nil
}

func verifyPeopleSoftToken(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 40 || !isHex(parts[0]) || len(parts[1]) == 0 || !isHex(parts[1]) {
		return false, errors.New("invalid PeopleSoft PS_TOKEN record")
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil || len(salt) > maxKDFFieldSize {
		return false, errors.New("invalid PeopleSoft PS_TOKEN salt")
	}
	h := sha1.New()
	_, _ = h.Write(salt)
	_, _ = h.Write(utf16le(candidate))
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[0]), nil
}

func verifyJavaHashCode(target, candidate string) (bool, error) {
	if len(target) != 8 || !isHex(target) {
		return false, errors.New("invalid Java hashCode record")
	}
	var got uint32
	for _, b := range []byte(candidate) {
		got = got*31 + uint32(b)
	}
	want, _ := strconv.ParseUint(target, 16, 32)
	return got == uint32(want), nil
}

func verifyRailsRestfulAuth(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 3 || len(parts[0]) != 40 || !isHex(parts[0]) || parts[1] == "" || parts[2] == "" {
		return false, errors.New("invalid Rails Restful-Authentication record")
	}
	salt, siteKey := parts[1], parts[2]
	got := sha1HexString(siteKey + "--" + salt + "--" + candidate + "--" + siteKey)
	for i := 0; i < 9; i++ {
		got = sha1HexString(got + "--" + salt + "--" + candidate + "--" + siteKey)
	}
	return strings.EqualFold(got, parts[0]), nil
}

func sha1HexString(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func verifyWeb2pyPBKDF2(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "pbkdf2(") || !strings.HasSuffix(parts[0], ")") {
		return false, errors.New("invalid Web2py PBKDF2 record")
	}
	params := strings.Split(strings.TrimSuffix(strings.TrimPrefix(parts[0], "pbkdf2("), ")"), ",")
	if len(params) != 3 || params[2] != "sha512" {
		return false, errors.New("unsupported Web2py PBKDF2 parameters")
	}
	iterations, err := strconv.Atoi(params[0])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Web2py PBKDF2 iteration count")
	}
	wantLen, err := strconv.Atoi(params[1])
	if err != nil || wantLen < 1 || wantLen > maxKDFFieldSize || len(parts[2]) != wantLen*2 || !isHex(parts[2]) {
		return false, errors.New("invalid Web2py PBKDF2 digest length")
	}
	want, _ := hex.DecodeString(parts[2])
	got := pbkdf2.Key([]byte(candidate), []byte(parts[1]), iterations, wantLen, sha512.New)
	return bytesEqualCT(got, want), nil
}

func verifyFlaskSession(target, candidate string) (bool, error) {
	parts := strings.Split(target, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false, errors.New("invalid Flask session cookie")
	}
	salt := parts[0] + "." + parts[1]
	first := hmac.New(sha1.New, []byte(candidate))
	_, _ = first.Write([]byte("cookie-session"))
	second := hmac.New(sha1.New, first.Sum(nil))
	_, _ = second.Write([]byte(salt))
	want, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil || len(want) != sha1.Size {
		return false, errors.New("invalid Flask session signature")
	}
	return hmac.Equal(second.Sum(nil), want), nil
}

func verifyWordPressBcrypt(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$wp$2") {
		return false, errors.New("invalid WordPress bcrypt record")
	}
	mac := hmac.New(sha512.New384, []byte("wp-sha384"))
	_, _ = mac.Write([]byte(candidate))
	encoded := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return bcrypt.CompareHashAndPassword([]byte(target[3:]), []byte(encoded)) == nil, nil
}

func verifyKrb5DB(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "krb5db" ||
		parts[3] == "" || parts[4] == "" || !isHex(parts[5]) {
		return false, errors.New("invalid Kerberos 5 DB record")
	}
	keyLen := 0
	switch parts[2] {
	case "17":
		keyLen = 16
	case "18":
		keyLen = 32
	default:
		return false, errors.New("unsupported Kerberos 5 DB etype (want 17 or 18)")
	}
	if len(parts[5]) != keyLen*2 {
		return false, errors.New("invalid Kerberos 5 DB key length")
	}
	got := aesString2Key(candidate, strings.ToUpper(parts[4])+parts[3], keyLen)
	want, _ := hex.DecodeString(parts[5])
	return bytesEqualCT(got, want), nil
}

func verifyMySQLCRAM(target, candidate string) (bool, error) {
	const prefix = "$mysqlna$"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid MySQL CRAM-SHA1 record")
	}
	parts := strings.Split(strings.TrimPrefix(target, prefix), "*")
	if len(parts) != 2 || len(parts[0]) != 40 || !isHex(parts[0]) ||
		len(parts[1]) != 40 || !isHex(parts[1]) {
		return false, errors.New("invalid MySQL CRAM-SHA1 fields")
	}
	salt, _ := hex.DecodeString(parts[0])
	first := sha1.Sum([]byte(candidate))
	second := sha1.Sum(first[:])
	h := sha1.New()
	_, _ = h.Write(salt)
	_, _ = h.Write(second[:])
	challenge := h.Sum(nil)
	got := make([]byte, sha1.Size)
	for i := range got {
		got[i] = first[i] ^ challenge[i]
	}
	want, _ := hex.DecodeString(parts[1])
	return bytesEqualCT(got, want), nil
}

func verifyTACACSPlus(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "tacacs-plus" || parts[2] != "0" ||
		len(parts[3]) != 8 || !isHex(parts[3]) || len(parts[4]) < 12 || !isHex(parts[4]) ||
		len(parts[5]) != 4 || !isHex(parts[5]) {
		return false, errors.New("invalid TACACS+ record")
	}
	sessionID, _ := hex.DecodeString(parts[3])
	ciphertext, _ := hex.DecodeString(parts[4])
	versionSequence, _ := hex.DecodeString(parts[5])
	plaintext := make([]byte, len(ciphertext))
	var previous []byte
	for offset := 0; offset < len(ciphertext); offset += md5.Size {
		h := md5.New()
		_, _ = h.Write(sessionID)
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(versionSequence)
		_, _ = h.Write(previous)
		pad := h.Sum(nil)
		end := offset + md5.Size
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		for i := offset; i < end; i++ {
			plaintext[i] = ciphertext[i] ^ pad[i-offset]
		}
		previous = pad
	}
	if len(plaintext) < 6 {
		return false, nil
	}
	status, flags := plaintext[0], plaintext[1]
	validStatus := status >= 1 && status <= 7 || status == 0x21
	messageLen := int(binary.BigEndian.Uint16(plaintext[2:4]))
	dataLen := int(binary.BigEndian.Uint16(plaintext[4:6]))
	return validStatus && flags <= 1 && 6+messageLen+dataLen == len(plaintext), nil
}

func verifyAppleSecureNotes(target, candidate string) (bool, error) {
	parts := strings.Split(target, "*")
	if len(parts) != 5 || parts[0] != "$ASN$" || parts[1] != "1" ||
		len(parts[3]) != 32 || !isHex(parts[3]) || len(parts[4]) != 48 || !isHex(parts[4]) {
		return false, errors.New("invalid Apple Secure Notes record")
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Apple Secure Notes iteration count")
	}
	salt, _ := hex.DecodeString(parts[3])
	wrapped, _ := hex.DecodeString(parts[4])
	kek := pbkdf2.Key([]byte(candidate), salt, iterations, aes.BlockSize, sha256.New)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return false, err
	}
	var a [8]byte
	copy(a[:], wrapped[:8])
	p := [2][8]byte{}
	copy(p[0][:], wrapped[8:16])
	copy(p[1][:], wrapped[16:24])
	var in, out [aes.BlockSize]byte
	for j := 5; j >= 0; j-- {
		for i := 1; i >= 0; i-- {
			copy(in[:8], a[:])
			t := uint64(2*j + i + 1)
			for k := 0; k < 8; k++ {
				in[k] ^= byte(t >> (56 - 8*k))
			}
			copy(in[8:], p[i][:])
			block.Decrypt(out[:], in[:])
			copy(a[:], out[:8])
			copy(p[i][:], out[8:])
		}
	}
	return bytesEqualCT(a[:], []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}), nil
}

func verifyOracleOTM(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 4 || parts[0] != "otm_sha256" || parts[2] == "" || len(parts[2]) > maxKDFFieldSize {
		return false, errors.New("invalid Oracle OTM SHA-256 record")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Oracle OTM iteration count")
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != sha256.Size {
		return false, errors.New("invalid Oracle OTM digest")
	}
	first := sha256.Sum256(append([]byte(parts[2]), []byte(candidate)...))
	digest := first[:]
	for i := 1; i < iterations; i++ {
		next := sha256.Sum256(digest)
		digest = next[:]
	}
	return bytesEqualCT(digest, want), nil
}

func verifyXMPPSCRAM(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 7 || parts[0] != "" || parts[1] != "xmpp-scram" || parts[2] != "0" ||
		!isHex(parts[5]) || len(parts[6]) != 40 || !isHex(parts[6]) {
		return false, errors.New("invalid XMPP SCRAM record")
	}
	iterations, err := strconv.Atoi(parts[3])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid XMPP SCRAM iteration count")
	}
	saltLen, err := strconv.Atoi(parts[4])
	if err != nil || saltLen < 1 || saltLen > maxKDFFieldSize || len(parts[5]) != saltLen*2 {
		return false, errors.New("invalid XMPP SCRAM salt length")
	}
	salt, _ := hex.DecodeString(parts[5])
	saltedPassword := pbkdf2.Key([]byte(candidate), salt, iterations, sha1.Size, sha1.New)
	clientKeyMAC := hmac.New(sha1.New, saltedPassword)
	_, _ = clientKeyMAC.Write([]byte("Client Key"))
	storedKey := sha1.Sum(clientKeyMAC.Sum(nil))
	want, _ := hex.DecodeString(parts[6])
	return bytesEqualCT(storedKey[:], want), nil
}

func verifyOffice2016Sheet(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 7 || parts[0] != "" || parts[1] != "office" || parts[2] != "2016" || parts[3] != "0" {
		return false, errors.New("invalid Office 2016 sheet-protection record")
	}
	iterations, err := strconv.Atoi(parts[4])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Office 2016 sheet-protection iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil || len(salt) != aes.BlockSize {
		return false, errors.New("invalid Office 2016 sheet-protection salt")
	}
	want, err := base64.StdEncoding.DecodeString(parts[6])
	if err != nil || len(want) != sha512.Size {
		return false, errors.New("invalid Office 2016 sheet-protection digest")
	}
	h := sha512.New()
	_, _ = h.Write(salt)
	_, _ = h.Write(utf16le(candidate))
	digest := h.Sum(nil)
	var counter [4]byte
	for i := 0; i < iterations; i++ {
		binary.LittleEndian.PutUint32(counter[:], uint32(i))
		h.Reset()
		_, _ = h.Write(digest)
		_, _ = h.Write(counter[:])
		digest = h.Sum(digest[:0])
	}
	return bytesEqualCT(digest, want), nil
}
