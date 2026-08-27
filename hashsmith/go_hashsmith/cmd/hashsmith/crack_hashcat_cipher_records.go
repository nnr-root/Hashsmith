package main

// Small, self-contained Hashcat record formats built around standard cipher
// primitives or password-derived state. These records are useful for direct
// cross-tool comparisons because they use Hashcat's published text encoding.

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/encoding/japanese"
)

func parseKnownPlaintextBlock(target string) (ciphertext, plaintext []byte, err error) {
	fields := strings.Split(target, ":")
	if len(fields) != 2 || len(fields[0]) != 16 || len(fields[1]) != 16 {
		return nil, nil, errors.New("invalid known-plaintext cipher record (need 16-hex-ciphertext:16-hex-plaintext)")
	}
	ciphertext, err = hex.DecodeString(fields[0])
	if err != nil {
		return nil, nil, errors.New("invalid known-plaintext ciphertext")
	}
	plaintext, err = hex.DecodeString(fields[1])
	if err != nil {
		return nil, nil, errors.New("invalid known plaintext")
	}
	return ciphertext, plaintext, nil
}

func verifyDESKnownPlaintext(target, candidate string, triple bool) (bool, error) {
	want, plaintext, err := parseKnownPlaintextBlock(target)
	if err != nil {
		return false, err
	}
	keyLen := 8
	if triple {
		keyLen = 24
	}
	if len(candidate) != keyLen {
		return false, nil
	}
	var got = make([]byte, des.BlockSize)
	if triple {
		block, err := des.NewTripleDESCipher([]byte(candidate))
		if err != nil {
			return false, err
		}
		block.Encrypt(got, plaintext)
	} else {
		block, err := des.NewCipher([]byte(candidate))
		if err != nil {
			return false, err
		}
		block.Encrypt(got, plaintext)
	}
	return bytesEqualCT(got, want), nil
}

func chachaQuarterRound(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 7)
}

// chacha20OriginalBlock implements the original 64-bit-counter/64-bit-nonce
// ChaCha20 layout used by Hashcat mode 15400 and OpenSSH's ChaCha primitive.
func chacha20OriginalBlock(key []byte, counter, nonce uint64) [64]byte {
	return chachaOriginalBlock(key, counter, nonce, 20)
}

func chachaOriginalBlock(key []byte, counter, nonce uint64, rounds int) [64]byte {
	state := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12], state[13] = uint32(counter), uint32(counter>>32)
	state[14], state[15] = uint32(nonce), uint32(nonce>>32)
	x := state
	for i := 0; i < rounds/2; i++ {
		chachaQuarterRound(&x, 0, 4, 8, 12)
		chachaQuarterRound(&x, 1, 5, 9, 13)
		chachaQuarterRound(&x, 2, 6, 10, 14)
		chachaQuarterRound(&x, 3, 7, 11, 15)
		chachaQuarterRound(&x, 0, 5, 10, 15)
		chachaQuarterRound(&x, 1, 6, 11, 12)
		chachaQuarterRound(&x, 2, 7, 8, 13)
		chachaQuarterRound(&x, 3, 4, 9, 14)
	}
	var out [64]byte
	for i := range x {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+state[i])
	}
	return out
}

func verifyChaCha20KnownPlaintext(target, candidate string) (bool, error) {
	const prefix = "$chacha20$*"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid ChaCha20 record prefix")
	}
	fields := strings.Split(target[len(prefix):], "*")
	if len(fields) != 5 {
		return false, errors.New("invalid ChaCha20 record fields")
	}
	position, err := hex.DecodeString(fields[0])
	if err != nil || len(position) != 8 {
		return false, errors.New("invalid ChaCha20 counter")
	}
	offset, err := strconv.Atoi(fields[1])
	if err != nil || offset < 0 || offset > 63 {
		return false, errors.New("invalid ChaCha20 offset")
	}
	iv, err := hex.DecodeString(fields[2])
	if err != nil || len(iv) != 8 {
		return false, errors.New("invalid ChaCha20 IV")
	}
	plain, err := hex.DecodeString(fields[3])
	if err != nil || len(plain) != 8 {
		return false, errors.New("invalid ChaCha20 plaintext")
	}
	want, err := hex.DecodeString(fields[4])
	if err != nil || len(want) != 8 {
		return false, errors.New("invalid ChaCha20 ciphertext")
	}
	if len(candidate) != 32 {
		return false, nil
	}
	counter := binary.LittleEndian.Uint64(position)
	nonce := binary.LittleEndian.Uint64(iv)
	first := chacha20OriginalBlock([]byte(candidate), counter, nonce)
	stream := make([]byte, 0, 128)
	stream = append(stream, first[:]...)
	if offset > 56 {
		second := chacha20OriginalBlock([]byte(candidate), counter+1, nonce)
		stream = append(stream, second[:]...)
	}
	got := make([]byte, 8)
	for i := range got {
		got[i] = plain[i] ^ stream[offset+i]
	}
	return bytesEqualCT(got, want), nil
}

func verifyTripcode(target, candidate string) (bool, error) {
	if len(target) != 10 || !allCryptBase64(target) {
		return false, errors.New("invalid tripcode (need 10 crypt-base64 characters)")
	}
	encoded, err := japanese.ShiftJIS.NewEncoder().String(candidate)
	if err != nil {
		return false, nil
	}
	word := []byte(encoded)
	if len(word) < 1 || len(word) > 8 {
		return false, nil
	}
	salt := [2]byte{'.', '.'}
	for i := 0; i < 2 && i+1 < len(word); i++ {
		c := word[i+1]
		if c < '.' || c > 'z' {
			c = '.'
		}
		switch {
		case c >= ':' && c <= '@':
			c = 'A' + (c - ':')
		case c >= '[' && c <= '`':
			c = 'a' + (c - '[')
		}
		salt[i] = c
	}
	full, err := descryptRaw(string(word), string(salt[:]))
	if err != nil {
		return false, err
	}
	return full[len(full)-10:] == target, nil
}

func verifyMojolicious(target, candidate string) (bool, error) {
	separator := strings.LastIndex(target, "--")
	if separator < 1 || separator+66 != len(target) {
		return false, errors.New("invalid Mojolicious cookie record")
	}
	want, err := hex.DecodeString(target[separator+2:])
	if err != nil || len(want) != sha256.Size {
		return false, errors.New("invalid Mojolicious HMAC")
	}
	if len(candidate) > 64 {
		return false, nil
	}
	mac := hmac.New(sha256.New, []byte(candidate))
	mac.Write([]byte(target[:separator]))
	return hmac.Equal(mac.Sum(nil), want), nil
}

func parseBlockchainSecond(target string) (digest, salt []byte, iterations int, err error) {
	decoded, decodeErr := base64.StdEncoding.DecodeString(target)
	if decodeErr != nil || len(decoded) != 59 || string(decoded[:3]) != "bs:" {
		return nil, nil, 0, errors.New("invalid Blockchain second-password record")
	}
	wantCRC := binary.LittleEndian.Uint32(decoded[55:59])
	if crc32.ChecksumIEEE(decoded[:55]) != wantCRC {
		return nil, nil, 0, errors.New("invalid Blockchain second-password CRC")
	}
	iterations64 := uint64(binary.LittleEndian.Uint32(decoded[51:55]))
	if iterations64 < 1 || iterations64 > maxKDFIterations {
		return nil, nil, 0, errors.New("invalid Blockchain second-password iteration count")
	}
	return decoded[3:35], decoded[35:51], int(iterations64), nil
}

func verifyBlockchainSecond(target, candidate string) (bool, error) {
	want, salt, iterations, err := parseBlockchainSecond(target)
	if err != nil {
		return false, err
	}
	saltHex := hex.EncodeToString(salt)
	uuid := fmt.Sprintf("%s-%s-%s-%s-%s", saltHex[:8], saltHex[8:12], saltHex[12:16], saltHex[16:20], saltHex[20:])
	digest := sha256.Sum256([]byte(uuid + candidate))
	for i := 1; i < iterations; i++ {
		digest = sha256.Sum256(digest[:])
	}
	return bytesEqualCT(digest[:], want), nil
}

func verifyDCCNT(target, candidate string) (bool, error) {
	fields := strings.SplitN(target, ":", 2)
	if len(fields) != 2 || len(fields[0]) != 32 {
		return false, errors.New("invalid DCC-NT hash (need md4:username)")
	}
	want, err := hex.DecodeString(fields[0])
	if err != nil || len(want) != 16 {
		return false, errors.New("invalid DCC-NT digest")
	}
	ntHash, err := hex.DecodeString(candidate)
	if err != nil || len(ntHash) != 16 {
		return false, nil
	}
	return bytesEqualCT(dccKeyFromNTHash(ntHash, fields[1]), want), nil
}

func verifyDCC2NT(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$DCC2$") {
		return false, errors.New("invalid DCC2-NT hash prefix")
	}
	fields := strings.Split(target[len("$DCC2$"):], "#")
	if len(fields) != 3 {
		return false, errors.New("invalid DCC2-NT hash fields")
	}
	iterations, err := strconv.Atoi(fields[0])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid DCC2-NT iteration count")
	}
	want, err := hex.DecodeString(fields[2])
	if err != nil || len(want) != 16 {
		return false, errors.New("invalid DCC2-NT digest")
	}
	ntHash, err := hex.DecodeString(candidate)
	if err != nil || len(ntHash) != 16 {
		return false, nil
	}
	salt := utf16le(strings.ToLower(fields[1]))
	dcc := md4.New()
	dcc.Write(ntHash)
	dcc.Write(salt)
	got := pbkdf2.Key(dcc.Sum(nil), salt, iterations, 16, sha1.New)
	return bytesEqualCT(got, want), nil
}

func allCryptBase64(s string) bool {
	for i := range s {
		if !strings.ContainsRune(itoa64, rune(s[i])) {
			return false
		}
	}
	return true
}
