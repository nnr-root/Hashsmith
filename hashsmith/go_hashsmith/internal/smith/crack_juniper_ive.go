package smith

// Juniper IVE (Secure Access / Pulse Connect) — Hashcat 501.
//
//	3u+UR6n8<base64>
//
// There is no new cryptography here: the record is an ordinary md5crypt hash
// that the appliance stores wrapped, and hashcat's mode 501 runs the plain
// md5crypt kernel once its parser has unwrapped it. The wrapping is a fixed
// AES-128 key compiled into the product, so it protects the hash from a
// casual reader of the config file and from nothing else.
//
// The base64 payload decodes to 76 bytes: a 12-byte header followed by four
// AES blocks. The header doubles as the CBC IV, padded to sixteen bytes with
// four zeros. Decrypting yields the md5crypt string directly, NUL-padded:
//
//	$1$danastre$3Fq.tAOwWhm3BuuAGM0C21
//
// The key below is not a secret being disclosed — it ships in every copy of
// hashcat and of the appliance firmware, and the format is useless without it.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	juniperIVEPrefix     = "3u+UR6n8"
	juniperIVEHeaderLen  = 12
	juniperIVEDecodedLen = 76
)

// juniperIVEKey is the static AES-128 key Juniper uses to obscure the stored
// md5crypt hash. Fixed across every appliance; carried in hashcat as four
// byte-swapped words.
var juniperIVEKey = []byte{
	0xa6, 0x70, 0x7a, 0x7e, 0x8d, 0xf9, 0x10, 0x59,
	0xde, 0xa7, 0x0a, 0xe5, 0x2f, 0x9c, 0x24, 0x42,
}

// juniperIVEUnwrap recovers the md5crypt string a Juniper IVE record carries.
func juniperIVEUnwrap(target string) (string, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, juniperIVEPrefix) {
		return "", errors.New("not a Juniper IVE record")
	}
	raw, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return "", errors.New("Juniper IVE record must be base64")
	}
	if len(raw) != juniperIVEDecodedLen {
		return "", errors.New("Juniper IVE record must decode to 76 bytes")
	}
	block, err := aes.NewCipher(juniperIVEKey)
	if err != nil {
		return "", err
	}
	// The 12-byte header is the IV, zero-extended to the AES block size.
	iv := make([]byte, aes.BlockSize)
	copy(iv, raw[:juniperIVEHeaderLen])
	out := make([]byte, len(raw)-juniperIVEHeaderLen)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, raw[juniperIVEHeaderLen:])

	// The plaintext is NUL-padded out to the block boundary.
	if i := strings.IndexByte(string(out), 0); i >= 0 {
		out = out[:i]
	}
	inner := string(out)
	if !strings.HasPrefix(inner, "$1$") {
		return "", errors.New("Juniper IVE record did not unwrap to an md5crypt hash")
	}
	return inner, nil
}

func verifyJuniperIVE(target, candidate string) (bool, error) {
	inner, err := juniperIVEUnwrap(target)
	if err != nil {
		return false, err
	}
	return verifyMD5Crypt(inner, candidate)
}

// juniperIVEIsRecord reports whether a line looks like a Juniper IVE record,
// for detection. The prefix alone is a 48-bit constant, so requiring the
// length as well costs nothing and refuses a truncated paste early.
func juniperIVEIsRecord(s string) bool {
	if !strings.HasPrefix(s, juniperIVEPrefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == juniperIVEDecodedLen
}
