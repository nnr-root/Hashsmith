package smith

// MetaMask Mobile wallet — Hashcat 31900.
//
//	$metamaskMobile$<salt, base64>$<iv, hex>$<ciphertext, base64>
//
// The vault key is PBKDF2-HMAC-SHA512 at 5,000 rounds and the payload is
// AES-256-CBC. Unlike the desktop wallet (26600, already here) there is no
// authentication tag, so a guess is judged on the plaintext looking right
// rather than on a MAC.
//
// The plaintext is the vault JSON — a correct guess on Hashcat's own example
// record decrypts to `[{"type":"HD Key Tree","data":{"` — and what Hashcat
// checks is that all 32 decrypted bytes are printable ASCII. That is roughly a
// 2^-46 filter: weaker than a tag, far past what a wordlist run produces by
// accident, and the same rule Hashcat applies. A tighter test keyed on the
// JSON prefix would reject any vault whose serialisation differs, so the loose
// one is the right one to copy.
//
// One thing the record does not do what it looks like: the salt is hashed as
// the BASE64 TEXT, not as the bytes it decodes to. MetaMask stores it as a
// string and hands that string to PBKDF2, so decoding it first — the obvious
// reading — derives the wrong key.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const metamaskMobileIterations = 5000

type metamaskMobileRecord struct {
	salt []byte // the base64 TEXT of the salt, which is what gets hashed
	iv   []byte
	ct   []byte
}

func parseMetaMaskMobile(target string) (*metamaskMobileRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$metamaskMobile$") {
		return nil, errors.New("not a MetaMask Mobile record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$metamaskMobile$"), "$")
	if len(p) != 3 {
		return nil, errors.New("MetaMask Mobile record must be $metamaskMobile$<salt>$<iv>$<ct>")
	}
	m := &metamaskMobileRecord{}
	var err error
	// Decoded only to reject a malformed record; the text is what is hashed.
	if raw, err := base64.StdEncoding.DecodeString(p[0]); err != nil || len(raw) == 0 {
		return nil, errors.New("MetaMask Mobile salt must be base64")
	}
	m.salt = []byte(p[0])
	if m.iv, err = hex.DecodeString(p[1]); err != nil || len(m.iv) != aes.BlockSize {
		return nil, errors.New("MetaMask Mobile IV must be 16 hex-encoded bytes")
	}
	if m.ct, err = base64.StdEncoding.DecodeString(p[2]); err != nil {
		return nil, errors.New("MetaMask Mobile ciphertext must be base64")
	}
	// Two blocks is what the kernel reads and what the record carries; a
	// shorter one cannot be judged and a longer one is a different record.
	if len(m.ct) != 2*aes.BlockSize {
		return nil, errors.New("MetaMask Mobile ciphertext must be 32 bytes")
	}
	return m, nil
}

// printableASCII reports whether every byte is in the range Hashcat's
// is_valid_printable_8 accepts: space through tilde, nothing else.
func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func verifyMetaMaskMobile(target, candidate string) (bool, error) {
	m, err := parseMetaMaskMobile(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), m.salt, metamaskMobileIterations, 32, sha512.New)
	return metamaskMobileMatches(m, key)
}

// metamaskMobileMatches is the shared "does this key decrypt to a plausible
// vault" check. Used by verifyMetaMaskMobile for its single derived key
// and by the lane hasher (pbkdf2_lane_metamask_mobile.go) for each of a
// batch's.
func metamaskMobileMatches(m *metamaskMobileRecord, key []byte) (bool, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(m.ct))
	cipher.NewCBCDecrypter(block, m.iv).CryptBlocks(plain, m.ct)
	return printableASCII(plain), nil
}
