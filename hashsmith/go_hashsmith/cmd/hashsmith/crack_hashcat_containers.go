package main

// Verifiers for several Hashcat-native container records. Keeping the native
// syntax lets the same extracted target be fed to Hashsmith and Hashcat.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func boundedPositiveInt(text, label string, max int) (int, error) {
	v, err := strconv.Atoi(text)
	if err != nil || v <= 0 || v > max {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return v, nil
}

func decodeExactHex(text string, size int, label string) ([]byte, error) {
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("invalid %s", label)
	}
	return b, nil
}

func decodeExactBase64(text string, size int, label string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(text)
	if err != nil || (size >= 0 && len(b) != size) {
		return nil, fmt.Errorf("invalid %s", label)
	}
	return b, nil
}

func verifyHashcatPEM(target, candidate, algo string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 9 || parts[1] != "PEM" || (parts[2] != "1" && parts[2] != "2") {
		return false, errors.New("invalid Hashcat PEM record")
	}
	if (algo == "pkcs8-pem-sha1" && parts[2] != "1") || (algo == "pkcs8-pem-sha256" && parts[2] != "2") {
		return false, errors.New("PEM record does not match selected PRF mode")
	}
	cid, err := boundedPositiveInt(parts[3], "PEM cipher id", 4)
	if err != nil {
		return false, err
	}
	salt, err := decodeExactHex(parts[4], 8, "PEM salt")
	if err != nil {
		return false, err
	}
	iter, err := boundedPositiveInt(parts[5], "PEM iteration count", 100000000)
	if err != nil {
		return false, err
	}
	ivSize := 16
	keyLen := []int{0, 24, 16, 24, 32}[cid]
	if cid == 1 {
		ivSize = 8
	}
	iv, err := decodeExactHex(parts[6], ivSize, "PEM IV")
	if err != nil {
		return false, err
	}
	declared, err := boundedPositiveInt(parts[7], "PEM ciphertext length", maxDecodedSize)
	if err != nil {
		return false, err
	}
	ct, err := hex.DecodeString(parts[8])
	if err != nil || len(ct) != declared {
		return false, errors.New("invalid PEM ciphertext")
	}
	var block cipher.Block
	var key []byte
	if parts[2] == "1" {
		key = pbkdf2.Key([]byte(candidate), salt, iter, keyLen, sha1.New)
	} else {
		key = pbkdf2.Key([]byte(candidate), salt, iter, keyLen, sha256.New)
	}
	if cid == 1 {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil || len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return false, errors.New("invalid PEM cipher parameters")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	unpadded, ok := pkcs7Unpad(pt, block.BlockSize())
	return ok && len(unpadded) > 0 && unpadded[0] == 0x30, nil
}

func verifyJKSPrivateKey(target, candidate string) (bool, error) {
	parts := strings.Split(target, "*")
	if len(parts) != 7 || parts[0] != "$jksprivk$" {
		return false, errors.New("invalid JKS private-key record")
	}
	want, err := decodeExactHex(parts[1], 20, "JKS checksum")
	if err != nil {
		return false, err
	}
	iv, err := decodeExactHex(parts[2], 20, "JKS IV")
	if err != nil {
		return false, err
	}
	enc, err := hex.DecodeString(parts[3])
	if err != nil || len(enc) == 0 || len(enc) > maxDecodedSize {
		return false, errors.New("invalid JKS encrypted key")
	}
	pw := utf16be(candidate)
	digestInput := append(append([]byte{}, pw...), iv...)
	digest := sha1.Sum(digestInput)
	key := make([]byte, len(enc))
	for off := 0; off < len(enc); off += sha1.Size {
		n := sha1.Size
		if len(enc)-off < n {
			n = len(enc) - off
		}
		for i := 0; i < n; i++ {
			key[off+i] = enc[off+i] ^ digest[i]
		}
		next := append(append([]byte{}, pw...), digest[:]...)
		digest = sha1.Sum(next)
	}
	checkInput := append(append([]byte{}, pw...), key...)
	got := sha1.Sum(checkInput)
	return bytesEqualCT(got[:], want), nil
}

func verifyVMX(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 6 || parts[1] != "vmx" || parts[2] != "0" {
		return false, errors.New("invalid VMware VMX record")
	}
	iter, err := boundedPositiveInt(parts[3], "VMX iteration count", 100000000)
	if err != nil {
		return false, err
	}
	salt, err := decodeExactHex(parts[4], 16, "VMX salt")
	if err != nil {
		return false, err
	}
	ct, err := decodeExactHex(parts[5], 32, "VMX ciphertext")
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), salt, iter, 32, sha1.New)
	block, _ := aes.NewCipher(key)
	pt := make([]byte, 16)
	cipher.NewCBCDecrypter(block, ct[:16]).CryptBlocks(pt, ct[16:])
	return string(pt) == "type=key:cipher=", nil
}

func xtsMulX(tweak []byte) {
	carry := byte(0)
	for i := 0; i < 16; i++ {
		next := tweak[i] >> 7
		tweak[i] = tweak[i]<<1 | carry
		carry = next
	}
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}

func decryptXTSZeroTweak(key, ct []byte) ([]byte, error) {
	if (len(key) != 32 && len(key) != 64) || len(ct)%16 != 0 {
		return nil, errors.New("invalid AES-XTS parameters")
	}
	half := len(key) / 2
	dataCipher, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, err
	}
	tweakCipher, _ := aes.NewCipher(key[half:])
	tweak := make([]byte, 16)
	tweakCipher.Encrypt(tweak, tweak)
	pt := make([]byte, len(ct))
	tmp := make([]byte, 16)
	for off := 0; off < len(ct); off += 16 {
		for i := 0; i < 16; i++ {
			tmp[i] = ct[off+i] ^ tweak[i]
		}
		dataCipher.Decrypt(tmp, tmp)
		for i := 0; i < 16; i++ {
			pt[off+i] = tmp[i] ^ tweak[i]
		}
		xtsMulX(tweak)
	}
	return pt, nil
}

func verifyVirtualBox(target, candidate, algo string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 10 || parts[1] != "vbox" || parts[2] != "0" {
		return false, errors.New("invalid VirtualBox record")
	}
	iter1, err := boundedPositiveInt(parts[3], "VirtualBox first iteration count", 100000000)
	if err != nil {
		return false, err
	}
	salt1, err := decodeExactHex(parts[4], 32, "VirtualBox first salt")
	if err != nil {
		return false, err
	}
	keyWords, err := boundedPositiveInt(parts[5], "VirtualBox key length", 16)
	if err != nil || (keyWords != 8 && keyWords != 16) {
		return false, errors.New("invalid VirtualBox key length")
	}
	if (algo == "virtualbox-aes128" && keyWords != 8) || (algo == "virtualbox-aes256" && keyWords != 16) {
		return false, errors.New("VirtualBox record does not match selected AES-XTS mode")
	}
	enc, err := decodeExactHex(parts[6], keyWords*4, "VirtualBox encrypted password")
	if err != nil {
		return false, err
	}
	iter2, err := boundedPositiveInt(parts[7], "VirtualBox second iteration count", 100000000)
	if err != nil {
		return false, err
	}
	salt2, err := decodeExactHex(parts[8], 32, "VirtualBox second salt")
	if err != nil {
		return false, err
	}
	want, err := decodeExactHex(parts[9], 32, "VirtualBox checksum")
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), salt1, iter1, keyWords*4, sha256.New)
	plain, err := decryptXTSZeroTweak(key, enc)
	if err != nil {
		return false, err
	}
	got := pbkdf2.Key(plain, salt2, iter2, 32, sha256.New)
	return bytesEqualCT(got, want), nil
}

func verifyMetaMask(target, candidate string, short bool) (bool, error) {
	prefix := "$metamask$"
	if short {
		prefix = "$metamask-short$"
	}
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid MetaMask record")
	}
	parts := strings.Split(strings.TrimPrefix(target, prefix), "$")
	if len(parts) != 3 {
		return false, errors.New("invalid MetaMask field count")
	}
	salt, err := decodeExactBase64(parts[0], 32, "MetaMask salt")
	if err != nil {
		return false, err
	}
	nonce, err := decodeExactBase64(parts[1], 16, "MetaMask IV")
	if err != nil {
		return false, err
	}
	ct, err := decodeExactBase64(parts[2], -1, "MetaMask ciphertext")
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), salt, 10000, 32, sha256.New)
	if short {
		if len(ct) != 64 {
			return false, errors.New("invalid MetaMask short ciphertext length")
		}
		pt, err := gcmCTRDecrypt(key, nonce, ct)
		if err != nil {
			return false, err
		}
		for _, b := range pt {
			if b < 0x20 || b > 0x7e {
				return false, nil
			}
		}
		return true, nil
	}
	if len(ct) < 30 || len(ct) > 3136 || len(ct) < 16 {
		return false, errors.New("invalid MetaMask ciphertext length")
	}
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return false, err
	}
	_, err = gcm.Open(nil, nonce, ct, nil)
	return err == nil, nil
}

func gcmMul(x, y [16]byte) [16]byte {
	var z, v [16]byte
	v = y
	for i := 0; i < 128; i++ {
		if x[i/8]&(1<<uint(7-i%8)) != 0 {
			for j := range z {
				z[j] ^= v[j]
			}
		}
		lsb := v[15] & 1
		carry := byte(0)
		for j := 0; j < 16; j++ {
			next := v[j] & 1
			v[j] = v[j]>>1 | carry<<7
			carry = next
		}
		if lsb != 0 {
			v[0] ^= 0xe1
		}
	}
	return z
}

func gcmJ0(block cipher.Block, nonce []byte) [16]byte {
	var zero, h, y, n [16]byte
	block.Encrypt(h[:], zero[:])
	nonceLen := len(nonce)
	if len(nonce) == 12 {
		copy(y[:12], nonce)
		y[15] = 1
		return y
	}
	for len(nonce) >= 16 {
		copy(n[:], nonce[:16])
		for i := range y {
			y[i] ^= n[i]
		}
		y = gcmMul(y, h)
		nonce = nonce[16:]
	}
	if len(nonce) > 0 {
		n = [16]byte{}
		copy(n[:], nonce)
		for i := range y {
			y[i] ^= n[i]
		}
		y = gcmMul(y, h)
	}
	var lengths [16]byte
	binary.BigEndian.PutUint64(lengths[8:], uint64(nonceLen)*8)
	for i := range y {
		y[i] ^= lengths[i]
	}
	return gcmMul(y, h)
}

func gcmCTRDecrypt(key, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counter := gcmJ0(block, nonce)
	pt := make([]byte, len(ct))
	stream := make([]byte, 16)
	for off := 0; off < len(ct); off += 16 {
		v := binary.BigEndian.Uint32(counter[12:]) + 1
		binary.BigEndian.PutUint32(counter[12:], v)
		block.Encrypt(stream, counter[:])
		n := 16
		if len(ct)-off < n {
			n = len(ct) - off
		}
		for i := 0; i < n; i++ {
			pt[off+i] = ct[off+i] ^ stream[i]
		}
	}
	return pt, nil
}

func verifyExodus(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 8 || parts[0] != "EXODUS" {
		return false, errors.New("invalid Exodus record")
	}
	n, err := boundedPositiveInt(parts[1], "Exodus scrypt N", 1<<24)
	if err != nil || n&(n-1) != 0 {
		return false, errors.New("invalid Exodus scrypt N")
	}
	r, err := boundedPositiveInt(parts[2], "Exodus scrypt r", 1024)
	if err != nil {
		return false, err
	}
	p, err := boundedPositiveInt(parts[3], "Exodus scrypt p", 1024)
	if err != nil {
		return false, err
	}
	if uint64(128)*uint64(n)*uint64(r) > maxScryptMemory || uint64(r)*uint64(p) >= 1<<30 {
		return false, errors.New("unsafe Exodus scrypt work factors")
	}
	salt, err := decodeExactBase64(parts[4], 32, "Exodus salt")
	if err != nil {
		return false, err
	}
	nonce, err := decodeExactBase64(parts[5], 12, "Exodus IV")
	if err != nil {
		return false, err
	}
	ct, err := decodeExactBase64(parts[6], -1, "Exodus ciphertext")
	if err != nil || len(ct) == 0 || len(ct) > maxKDFFieldSize {
		return false, errors.New("invalid Exodus ciphertext")
	}
	tag, err := decodeExactBase64(parts[7], 16, "Exodus tag")
	if err != nil {
		return false, err
	}
	key, err := scrypt.Key([]byte(candidate), salt, n, r, p, 32)
	if err != nil {
		return false, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	sealed := append(append([]byte{}, ct...), tag...)
	_, err = gcm.Open(nil, nonce, sealed, nil)
	return err == nil, nil
}
