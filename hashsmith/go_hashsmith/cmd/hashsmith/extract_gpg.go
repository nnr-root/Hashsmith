package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ripemd160"
)

// ── GPG symmetric-encryption extraction (gpg2smith) ────────────────────────────
//
// Handles files produced by `gpg -c` (symmetric passphrase encryption): an
// OpenPGP message with a Symmetric-Key ESK packet (tag 3, S2K parameters) and a
// Symmetrically Encrypted Integrity Protected Data packet (tag 18). The session
// key is the S2K output; verification decrypts the SEIPD and checks the two-byte
// quick-check and the trailing MDC (SHA-1).
//
// Hashsmith format:
//   $gpg$<s2ktype>$<hashalgo>$<cipher>$<count>$<salt_hex>$<seipd_hex>

func extractGPG(path string) (*zipHashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	// Accept ASCII-armored files too (gpg -c -a).
	if bytes.Contains(data, []byte("-----BEGIN PGP MESSAGE-----")) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("cannot decode PGP armor: %w", err)
		}
		raw, err := io.ReadAll(block.Body)
		if err != nil {
			return nil, err
		}
		data = raw
	}

	skesk, seipd, err := findGPGPackets(data)
	if err != nil {
		return nil, err
	}

	// SKESK body: version(1) cipher(1) s2k_type(1) hash(1) [salt(8)] [count(1)]
	if len(skesk) < 4 || skesk[0] != 4 {
		return nil, errors.New("unsupported SKESK packet (need version 4)")
	}
	cipherAlgo := int(skesk[1])
	s2kType := int(skesk[2])
	hashAlgo := int(skesk[3])
	p := 4
	var salt []byte
	count := 0
	switch s2kType {
	case 0: // simple
	case 1: // salted
		if len(skesk) < p+8 {
			return nil, errors.New("truncated S2K salt")
		}
		salt = skesk[p : p+8]
		p += 8
	case 3: // iterated + salted
		if len(skesk) < p+9 {
			return nil, errors.New("truncated iterated S2K")
		}
		salt = skesk[p : p+8]
		p += 8
		count = gpgDecodeCount(skesk[p])
	default:
		return nil, fmt.Errorf("unsupported S2K type %d", s2kType)
	}
	if len(skesk) > p+1 {
		return nil, errors.New("this GPG file encrypts a session key (public-key or --symkey style) — only pure `gpg -c` is supported")
	}
	if _, _, err := gpgCipherParams(cipherAlgo); err != nil {
		return nil, err
	}
	if _, err := gpgHashNew(hashAlgo); err != nil {
		return nil, err
	}

	// SEIPD body: version(1) + CFB-encrypted data.
	if len(seipd) < 2 || seipd[0] != 1 {
		return nil, errors.New("unsupported SEIPD packet (need version 1)")
	}
	enc := seipd[1:]

	hashStr := fmt.Sprintf("$gpg$%d$%d$%d$%d$%s$%s",
		s2kType, hashAlgo, cipherAlgo, count,
		hex.EncodeToString(salt), hex.EncodeToString(enc))
	return &zipHashResult{
		hashType: "gpg",
		hash:     hashStr,
		filename: path,
		encLabel: fmt.Sprintf("GPG symmetric (%s, S2K type %d, %s)",
			gpgCipherLabel(cipherAlgo), s2kType, gpgHashLabel(hashAlgo)),
	}, nil
}

// ── OpenPGP packet parsing ──────────────────────────────────────────────────────

// findGPGPackets returns the SKESK (tag 3) and SEIPD (tag 18) packet bodies.
func findGPGPackets(data []byte) (skesk, seipd []byte, err error) {
	pos := 0
	for pos < len(data) {
		tag, body, next, perr := readPGPPacket(data, pos)
		if perr != nil {
			return nil, nil, perr
		}
		switch tag {
		case 3:
			skesk = body
		case 18:
			seipd = body
		}
		pos = next
	}
	if skesk == nil {
		return nil, nil, errors.New("no symmetric-key ESK packet found (not a `gpg -c` file?)")
	}
	if seipd == nil {
		return nil, nil, errors.New("no encrypted-data packet found")
	}
	return skesk, seipd, nil
}

// readPGPPacket parses one OpenPGP packet (old or new format, including partial
// body lengths) and returns its tag, body, and the offset of the next packet.
func readPGPPacket(data []byte, pos int) (tag int, body []byte, next int, err error) {
	if pos >= len(data) {
		return 0, nil, 0, errors.New("unexpected end of OpenPGP data")
	}
	ctb := data[pos]
	pos++
	if ctb&0x80 == 0 {
		return 0, nil, 0, errors.New("invalid OpenPGP packet tag")
	}

	if ctb&0x40 != 0 {
		// New-format packet.
		tag = int(ctb & 0x3f)
		var buf []byte
		for {
			if pos >= len(data) {
				return 0, nil, 0, errors.New("truncated new-format length")
			}
			l := int(data[pos])
			pos++
			var chunk int
			partial := false
			switch {
			case l < 192:
				chunk = l
			case l < 224:
				if pos >= len(data) {
					return 0, nil, 0, errors.New("truncated 2-octet length")
				}
				chunk = (l-192)<<8 + int(data[pos]) + 192
				pos++
			case l == 255:
				if pos+4 > len(data) {
					return 0, nil, 0, errors.New("truncated 5-octet length")
				}
				chunk = int(binary.BigEndian.Uint32(data[pos:]))
				pos += 4
			default: // 224..254 → partial body length
				chunk = 1 << (l & 0x1f)
				partial = true
			}
			if pos+chunk > len(data) {
				return 0, nil, 0, errors.New("packet body exceeds data")
			}
			buf = append(buf, data[pos:pos+chunk]...)
			pos += chunk
			if !partial {
				break
			}
		}
		return tag, buf, pos, nil
	}

	// Old-format packet.
	tag = int((ctb >> 2) & 0x0f)
	lenType := ctb & 0x03
	var length int
	switch lenType {
	case 0:
		if pos >= len(data) {
			return 0, nil, 0, errors.New("truncated 1-octet length")
		}
		length = int(data[pos])
		pos++
	case 1:
		if pos+2 > len(data) {
			return 0, nil, 0, errors.New("truncated 2-octet length")
		}
		length = int(binary.BigEndian.Uint16(data[pos:]))
		pos += 2
	case 2:
		if pos+4 > len(data) {
			return 0, nil, 0, errors.New("truncated 4-octet length")
		}
		length = int(binary.BigEndian.Uint32(data[pos:]))
		pos += 4
	default: // indeterminate: rest of file
		length = len(data) - pos
	}
	if pos+length > len(data) {
		return 0, nil, 0, errors.New("packet body exceeds data")
	}
	return tag, data[pos : pos+length], pos + length, nil
}

// gpgDecodeCount decodes the S2K iterated count octet (RFC 4880 §3.7.1.3).
func gpgDecodeCount(c byte) int {
	return (16 + int(c&15)) << ((c >> 4) + 6)
}

// ── S2K + cipher primitives ─────────────────────────────────────────────────────

func gpgHashNew(algo int) (func() hash.Hash, error) {
	switch algo {
	case 1:
		return md5.New, nil
	case 2:
		return sha1.New, nil
	case 3:
		return ripemd160.New, nil
	case 8:
		return sha256.New, nil
	case 9:
		return sha512.New384, nil
	case 10:
		return sha512.New, nil
	case 11:
		return sha256.New224, nil
	}
	return nil, fmt.Errorf("unsupported OpenPGP hash algorithm %d", algo)
}

func gpgHashLabel(a int) string {
	return map[int]string{1: "MD5", 2: "SHA1", 3: "RIPEMD160", 8: "SHA256", 9: "SHA384", 10: "SHA512", 11: "SHA224"}[a]
}

// gpgCipherParams returns (keyLen, blockSize) for an OpenPGP cipher algorithm.
func gpgCipherParams(algo int) (keyLen, blockSize int, err error) {
	switch algo {
	case 2:
		return 24, 8, nil // 3DES
	case 3:
		return 16, 8, nil // CAST5
	case 7:
		return 16, 16, nil // AES-128
	case 8:
		return 24, 16, nil // AES-192
	case 9:
		return 32, 16, nil // AES-256
	}
	return 0, 0, fmt.Errorf("unsupported OpenPGP cipher algorithm %d", algo)
}

func gpgCipherLabel(a int) string {
	return map[int]string{2: "3DES", 3: "CAST5", 7: "AES-128", 8: "AES-192", 9: "AES-256"}[a]
}

func gpgNewBlock(algo int, key []byte) (cipher.Block, error) {
	switch algo {
	case 2:
		return des.NewTripleDESCipher(key)
	case 3:
		return cast5.NewCipher(key)
	case 7, 8, 9:
		return aes.NewCipher(key)
	}
	return nil, fmt.Errorf("unsupported OpenPGP cipher algorithm %d", algo)
}

// gpgS2K derives the session key from the passphrase (RFC 4880 §3.7).
func gpgS2K(pass, salt []byte, s2kType, hashAlgo, count, keyLen int) ([]byte, error) {
	newHash, err := gpgHashNew(hashAlgo)
	if err != nil {
		return nil, err
	}
	digestLen := newHash().Size()
	numCtx := (keyLen + digestLen - 1) / digestLen

	out := make([]byte, 0, numCtx*digestLen)
	for ctx := 0; ctx < numCtx; ctx++ {
		h := newHash()
		h.Write(make([]byte, ctx)) // preload ctx zero bytes for extra key material
		switch s2kType {
		case 0:
			h.Write(pass)
		case 1:
			h.Write(salt)
			h.Write(pass)
		case 3:
			data := append(append([]byte{}, salt...), pass...)
			total := count
			if total < len(data) {
				total = len(data)
			}
			full := total / len(data)
			rem := total % len(data)
			for i := 0; i < full; i++ {
				h.Write(data)
			}
			if rem > 0 {
				h.Write(data[:rem])
			}
		default:
			return nil, fmt.Errorf("unsupported S2K type %d", s2kType)
		}
		out = append(out, h.Sum(nil)...)
	}
	return out[:keyLen], nil
}

// ── Verification ────────────────────────────────────────────────────────────────

// verifyGPG derives the session key, decrypts the SEIPD in OpenPGP-CFB mode, and
// checks the two-byte quick-check plus the trailing MDC (SHA-1).
func verifyGPG(targetHash, candidate string) (bool, error) {
	// $gpg$<s2ktype>$<hashalgo>$<cipher>$<count>$<salt_hex>$<seipd_hex>
	parts := strings.Split(targetHash, "$")
	if len(parts) != 8 || parts[1] != "gpg" {
		return false, errors.New("invalid gpg hash format")
	}
	var s2kType, hashAlgo, cipherAlgo, count int
	if _, err := fmt.Sscanf(parts[2], "%d", &s2kType); err != nil {
		return false, errors.New("invalid gpg s2k type")
	}
	if _, err := fmt.Sscanf(parts[3], "%d", &hashAlgo); err != nil {
		return false, errors.New("invalid gpg hash algo")
	}
	if _, err := fmt.Sscanf(parts[4], "%d", &cipherAlgo); err != nil {
		return false, errors.New("invalid gpg cipher algo")
	}
	if _, err := fmt.Sscanf(parts[5], "%d", &count); err != nil {
		return false, errors.New("invalid gpg count")
	}
	salt, err := hex.DecodeString(parts[6])
	if err != nil {
		return false, errors.New("invalid gpg salt")
	}
	enc, err := hex.DecodeString(parts[7])
	if err != nil {
		return false, errors.New("invalid gpg data")
	}

	keyLen, blockSize, err := gpgCipherParams(cipherAlgo)
	if err != nil {
		return false, err
	}
	if len(enc) < blockSize+2+22 {
		return false, errors.New("gpg SEIPD data too short")
	}

	key, err := gpgS2K([]byte(candidate), salt, s2kType, hashAlgo, count, keyLen)
	if err != nil {
		return false, err
	}
	block, err := gpgNewBlock(cipherAlgo, key)
	if err != nil {
		return false, err
	}

	plain := make([]byte, len(enc))
	iv := make([]byte, blockSize)
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, enc)

	// Quick-check: bytes [bs-2],[bs-1] repeat at [bs],[bs+1].
	if plain[blockSize-2] != plain[blockSize] || plain[blockSize-1] != plain[blockSize+1] {
		return false, nil
	}

	// MDC: last 22 bytes are 0xD3 0x14 || SHA-1(everything up to and incl. 0xD3 0x14).
	mdcStart := len(plain) - 22
	if plain[mdcStart] != 0xD3 || plain[mdcStart+1] != 0x14 {
		return false, nil
	}
	sum := sha1.Sum(plain[:mdcStart+2])
	return bytes.Equal(sum[:], plain[mdcStart+2:]), nil
}
