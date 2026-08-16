package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ── SSH private-key extraction (ssh2smith) ─────────────────────────────────────
//
// Produces a crackable hash from a password-protected SSH private key, covering:
//
//   • Modern OpenSSH keys ("-----BEGIN OPENSSH PRIVATE KEY-----"), which use the
//     bcrypt_pbkdf KDF and an AES cipher.  Hashsmith format:
//         $ssh$openssh$<cipher>$<rounds>$<salt_hex>$<firstblock_hex>
//
//   • Legacy PEM keys ("-----BEGIN RSA/EC/DSA PRIVATE KEY-----" with
//     "Proc-Type: 4,ENCRYPTED"), which use OpenSSL's EVP_BytesToKey (MD5).
//     Hashsmith format:
//         $ssh$pem$<cipher>$<iv_hex>$<ciphertext_hex>

const openSSHMagic = "openssh-key-v1\x00"

var dekInfoRe = regexp.MustCompile(`(?i)DEK-Info:\s*([A-Za-z0-9-]+),([0-9A-Fa-f]+)`)

// extractSSHKey reads an SSH private key file and returns a crackable hash.
func extractSSHKey(path string) (*zipHashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	text := string(data)

	switch {
	case strings.Contains(text, "BEGIN OPENSSH PRIVATE KEY"):
		return extractOpenSSHKey(text, path)
	case strings.Contains(text, "Proc-Type:") && strings.Contains(text, "ENCRYPTED"):
		return extractLegacyPEMKey(text, path)
	case strings.Contains(text, "BEGIN ENCRYPTED PRIVATE KEY"):
		return extractPKCS8Key(text, path)
	case strings.Contains(text, "PRIVATE KEY"):
		return nil, errors.New("this SSH private key is not password-protected")
	default:
		return nil, errors.New("not an SSH private key (no PEM header found)")
	}
}

// ── Modern OpenSSH format ───────────────────────────────────────────────────────

func extractOpenSSHKey(text, path string) (*zipHashResult, error) {
	blob, err := decodePEMBody(text, "OPENSSH PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(blob), openSSHMagic) {
		return nil, errors.New("invalid OpenSSH private key magic")
	}
	p := sshParser{buf: blob[len(openSSHMagic):]}

	cipher, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("cannot read cipher name: %w", err)
	}
	kdfName, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("cannot read kdf name: %w", err)
	}
	kdfOpts, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("cannot read kdf options: %w", err)
	}
	if string(cipher) == "none" || string(kdfName) == "none" {
		return nil, errors.New("this OpenSSH key is not password-protected")
	}
	if string(kdfName) != "bcrypt" {
		return nil, fmt.Errorf("unsupported OpenSSH KDF %q (only bcrypt)", kdfName)
	}

	// kdfoptions = string(salt) || uint32(rounds)
	kp := sshParser{buf: kdfOpts}
	salt, err := kp.readString()
	if err != nil {
		return nil, fmt.Errorf("cannot read KDF salt: %w", err)
	}
	rounds, err := kp.readUint32()
	if err != nil {
		return nil, fmt.Errorf("cannot read KDF rounds: %w", err)
	}

	// numKeys, then each public key, then the encrypted private section.
	if _, err := p.readUint32(); err != nil { // number of keys
		return nil, err
	}
	if _, err := p.readString(); err != nil { // public key
		return nil, err
	}
	encPriv, err := p.readString() // encrypted private section
	if err != nil {
		return nil, fmt.Errorf("cannot read encrypted private section: %w", err)
	}
	if len(encPriv) < 16 {
		return nil, errors.New("OpenSSH encrypted section too short")
	}

	// Only the first cipher block is needed to recover the two check integers.
	first := encPriv[:16]
	cipherName := string(cipher)
	if _, _, _, err := sshCipherParams(cipherName); err != nil {
		return nil, err
	}

	hash := fmt.Sprintf("$ssh$openssh$%s$%d$%s$%s",
		cipherName, rounds, hex.EncodeToString(salt), hex.EncodeToString(first))
	return &zipHashResult{
		hashType: "ssh",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("OpenSSH private key (%s, bcrypt %d rounds)", cipherName, rounds),
	}, nil
}

// sshCipherParams returns (keyLen, ivLen, mode) for an OpenSSH cipher name.
// mode is "ctr" or "cbc".
func sshCipherParams(name string) (keyLen, ivLen int, mode string, err error) {
	switch name {
	case "aes128-ctr":
		return 16, 16, "ctr", nil
	case "aes192-ctr":
		return 24, 16, "ctr", nil
	case "aes256-ctr":
		return 32, 16, "ctr", nil
	case "aes128-cbc":
		return 16, 16, "cbc", nil
	case "aes192-cbc":
		return 24, 16, "cbc", nil
	case "aes256-cbc":
		return 32, 16, "cbc", nil
	}
	return 0, 0, "", fmt.Errorf("unsupported OpenSSH cipher %q", name)
}

// ── Legacy PEM (OpenSSL) format ─────────────────────────────────────────────────

func extractLegacyPEMKey(text, path string) (*zipHashResult, error) {
	m := dekInfoRe.FindStringSubmatch(text)
	if m == nil {
		return nil, errors.New("encrypted PEM key without a DEK-Info header")
	}
	cipher := strings.ToUpper(m[1])
	iv, err := hex.DecodeString(m[2])
	if err != nil {
		return nil, fmt.Errorf("invalid DEK-Info IV: %w", err)
	}
	if _, _, err := pemCipherParams(cipher); err != nil {
		return nil, err
	}

	// The base64 body follows the blank line after the headers.
	keyType := pemKeyType(text)
	body, err := decodePEMBody(text, keyType)
	if err != nil {
		return nil, err
	}

	hash := fmt.Sprintf("$ssh$pem$%s$%s$%s",
		cipher, hex.EncodeToString(iv), hex.EncodeToString(body))
	return &zipHashResult{
		hashType: "ssh",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("Legacy PEM private key (%s)", cipher),
	}, nil
}

// pemKeyType returns the PEM label between BEGIN and PRIVATE (e.g. "RSA PRIVATE KEY").
func pemKeyType(text string) string {
	for _, t := range []string{"RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"} {
		if strings.Contains(text, "BEGIN "+t) {
			return t
		}
	}
	return "PRIVATE KEY"
}

// pemCipherParams returns (keyLen, blockSize) for a legacy PEM DEK-Info cipher.
func pemCipherParams(cipher string) (keyLen, blockSize int, err error) {
	switch cipher {
	case "AES-128-CBC":
		return 16, 16, nil
	case "AES-192-CBC":
		return 24, 16, nil
	case "AES-256-CBC":
		return 32, 16, nil
	case "DES-EDE3-CBC":
		return 24, 8, nil
	case "DES-CBC":
		return 8, 8, nil
	}
	return 0, 0, fmt.Errorf("unsupported PEM cipher %q", cipher)
}

// ── PEM / SSH-blob helpers ──────────────────────────────────────────────────────

// decodePEMBody returns the base64-decoded bytes between the BEGIN/END markers of
// the named PEM block, skipping any header lines (e.g. Proc-Type / DEK-Info).
func decodePEMBody(text, label string) ([]byte, error) {
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
	bi := strings.Index(text, begin)
	ei := strings.Index(text, end)
	if bi < 0 || ei < 0 || ei <= bi {
		return nil, fmt.Errorf("PEM block %q not found", label)
	}
	inner := text[bi+len(begin) : ei]

	var b64 strings.Builder
	for _, line := range strings.Split(inner, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, ":") {
			continue // blank line or a header such as DEK-Info:
		}
		b64.WriteString(line)
	}
	out, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in PEM body: %w", err)
	}
	return out, nil
}

// ── Verification ────────────────────────────────────────────────────────────────

// verifySSH checks an SSH private-key password for both Hashsmith SSH formats.
func verifySSH(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	// "$ssh$<subtype>$..." → ["", "ssh", subtype, ...]
	if len(parts) < 3 || parts[1] != "ssh" {
		return false, errors.New("invalid ssh hash format")
	}
	switch parts[2] {
	case "openssh":
		return verifyOpenSSH(parts, candidate)
	case "pem":
		return verifyPEMKey(parts, candidate)
	}
	return false, fmt.Errorf("unknown ssh hash subtype %q", parts[2])
}

// verifyOpenSSH derives the bcrypt_pbkdf key, decrypts the first block of the
// private section, and checks that the two OpenSSH check integers match.
func verifyOpenSSH(parts []string, candidate string) (bool, error) {
	// $ssh$openssh$<cipher>$<rounds>$<salt_hex>$<firstblock_hex>
	if len(parts) != 7 {
		return false, errors.New("invalid openssh hash format")
	}
	cipherName := parts[3]
	var rounds int
	if _, err := fmt.Sscanf(parts[4], "%d", &rounds); err != nil {
		return false, errors.New("invalid openssh rounds")
	}
	salt, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid openssh salt")
	}
	first, err := hex.DecodeString(parts[6])
	if err != nil || len(first) < 16 {
		return false, errors.New("invalid openssh first block")
	}

	keyLen, ivLen, mode, err := sshCipherParams(cipherName)
	if err != nil {
		return false, err
	}
	derived, err := bcryptPBKDF([]byte(candidate), salt, keyLen+ivLen, rounds)
	if err != nil {
		return false, err
	}
	key, iv := derived[:keyLen], derived[keyLen:keyLen+ivLen]

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	dec := make([]byte, 16)
	switch mode {
	case "ctr":
		cipher.NewCTR(block, iv).XORKeyStream(dec, first[:16])
	case "cbc":
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, first[:16])
	default:
		return false, fmt.Errorf("unsupported ssh cipher mode %q", mode)
	}

	// The decrypted private section begins with two identical 4-byte check ints.
	return binary.BigEndian.Uint32(dec[0:4]) == binary.BigEndian.Uint32(dec[4:8]), nil
}

// verifyPEMKey derives the OpenSSL EVP_BytesToKey key, decrypts the PEM body, and
// checks for valid PKCS#7 padding plus a leading DER SEQUENCE tag.
func verifyPEMKey(parts []string, candidate string) (bool, error) {
	// $ssh$pem$<cipher>$<iv_hex>$<ciphertext_hex>
	if len(parts) != 6 {
		return false, errors.New("invalid pem hash format")
	}
	cipherName := parts[3]
	iv, err := hex.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid pem iv")
	}
	ct, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid pem ciphertext")
	}
	keyLen, blockSize, err := pemCipherParams(cipherName)
	if err != nil {
		return false, err
	}
	if len(ct) == 0 || len(ct)%blockSize != 0 || len(iv) < blockSize {
		return false, errors.New("pem ciphertext not block-aligned")
	}

	// OpenSSL derives the key with EVP_BytesToKey(MD5); the salt is the first
	// 8 bytes of the IV.
	key := evpBytesToKeyMD5([]byte(candidate), iv[:8], keyLen)

	var block cipher.Block
	switch blockSize {
	case 16:
		block, err = aes.NewCipher(key)
	case 8:
		if cipherName == "DES-EDE3-CBC" {
			block, err = des.NewTripleDESCipher(key)
		} else {
			block, err = des.NewCipher(key)
		}
	}
	if err != nil {
		return false, err
	}

	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:blockSize]).CryptBlocks(pt, ct)

	// PKCS#7 padding check.
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > blockSize || pad > len(pt) {
		return false, nil
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return false, nil
		}
	}
	// A correctly decrypted key body is DER and starts with a SEQUENCE (0x30).
	return pt[0] == 0x30, nil
}

// evpBytesToKeyMD5 implements OpenSSL's EVP_BytesToKey with MD5 and one
// iteration — the KDF used for legacy "DEK-Info" encrypted PEM keys.
func evpBytesToKeyMD5(password, salt []byte, keyLen int) []byte {
	var out, prev []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// sshParser reads SSH wire-format fields (RFC 4251) from a byte buffer.
type sshParser struct{ buf []byte }

func (p *sshParser) readUint32() (uint32, error) {
	if len(p.buf) < 4 {
		return 0, errors.New("unexpected end of SSH data")
	}
	v := binary.BigEndian.Uint32(p.buf)
	p.buf = p.buf[4:]
	return v, nil
}

func (p *sshParser) readString() ([]byte, error) {
	n, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	if int(n) > len(p.buf) {
		return nil, errors.New("SSH string length exceeds buffer")
	}
	s := p.buf[:n]
	p.buf = p.buf[n:]
	return s, nil
}
