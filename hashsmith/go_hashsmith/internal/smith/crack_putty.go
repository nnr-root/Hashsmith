package smith

// PuTTY private keys (.ppk).
//
//	$putty$<v>*<block>*<?>*<?>*<MAC>*<public length>*<public blob>*
//	       <private length>*<private blob>*<algorithm>*<encryption>*<comment>
//
// A PPK file protects the private half with AES-256-CBC and then MACs the
// whole key — algorithm, cipher name, comment, public blob and the DECRYPTED
// private blob — so the MAC is what says whether the passphrase was right.
// That is why the check has to decrypt first: there is no verifier to compare
// against without doing so.
//
// Two details are PuTTY's own and neither is guessable from the file:
//
//   - The AES key is SHA-1 of a four-byte counter followed by the passphrase,
//     taken twice with the counter 0 and 1 and concatenated, of which the
//     first 32 bytes are used. No salt, no iterations — which is what makes a
//     PPK cheap to attack compared with an OpenSSH key.
//   - The MAC key is SHA-1 of the fixed string "putty-private-key-file-mac-key"
//     followed by the passphrase.
//
// Each MACed field is length-prefixed the way SSH encodes a string: four
// bytes of big-endian length, then the bytes.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const puttyPrefix = "$putty$"

// puttyMACKeySalt is the fixed string PuTTY hashes with the passphrase to key
// the MAC, spelled as it appears in PuTTY's source.
const puttyMACKeySalt = "putty-private-key-file-mac-key"

type puttyKey struct {
	mac                    []byte
	public, private        []byte
	algo, encryption, name string
}

func parsePutty(target string) (*puttyKey, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, puttyPrefix) {
		return nil, errors.New("not a PuTTY private key record")
	}
	f := strings.Split(t[len(puttyPrefix):], "*")
	if len(f) != 12 {
		return nil, errors.New("a PuTTY key record has twelve fields")
	}
	k := &puttyKey{algo: f[9], encryption: f[10], name: f[11]}
	if k.encryption != "aes256-cbc" {
		return nil, errors.New("this PuTTY key names " + k.encryption +
			", and only aes256-cbc is a protected key")
	}
	var err error
	if k.mac, err = decodeExactHex(f[4], sha1.Size, "PuTTY MAC"); err != nil {
		return nil, err
	}
	for _, x := range []struct {
		dst      *[]byte
		size, hx string
		name     string
	}{
		{&k.public, f[5], f[6], "public blob"},
		{&k.private, f[7], f[8], "private blob"},
	} {
		n, err := strconv.Atoi(x.size)
		if err != nil || n < 1 || n > maxKDFFieldSize*64 {
			return nil, errors.New("invalid PuTTY " + x.name + " length")
		}
		if *x.dst, err = hex.DecodeString(x.hx); err != nil || len(*x.dst) != n {
			return nil, errors.New("invalid PuTTY " + x.name)
		}
	}
	if len(k.private)%aes.BlockSize != 0 {
		return nil, errors.New("PuTTY private blob is not whole AES blocks")
	}
	if k.algo == "" || k.name == "" {
		return nil, errors.New("a PuTTY key record must name its algorithm")
	}
	return k, nil
}

// sshLengthPrefixed encodes one MACed field: four bytes of big-endian length
// then the bytes themselves.
func sshLengthPrefixed(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// verifyPutty checks a PuTTY key's passphrase.
func verifyPutty(target, candidate string) (bool, error) {
	k, err := parsePutty(target)
	if err != nil {
		return false, err
	}
	// The AES key: SHA-1 over a counter and the passphrase, twice.
	key := make([]byte, 0, 2*sha1.Size)
	for i := 0; i < 2; i++ {
		h := sha1.New()
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(i))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(candidate))
		key = h.Sum(key)
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(k.private))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, k.private)

	mk := sha1.New()
	_, _ = mk.Write([]byte(puttyMACKeySalt))
	_, _ = mk.Write([]byte(candidate))

	mac := hmac.New(sha1.New, mk.Sum(nil))
	for _, part := range [][]byte{
		[]byte(k.algo), []byte(k.encryption), []byte(k.name), k.public, plain,
	} {
		_, _ = mac.Write(sshLengthPrefixed(part))
	}
	return hmac.Equal(mac.Sum(nil), k.mac), nil
}

func isPutty(target string) bool {
	_, err := parsePutty(target)
	return err == nil
}
