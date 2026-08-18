package main

// BitLocker (password-protected volume) cracking.
//
// The AES key is stretched from the password with a 1,048,576-iteration SHA-256
// chain, then used in AES-CTR to decrypt the VMK blob. A correct password is
// proven by fixed structure bytes in the decrypted VMK (its size, version, and
// key-type fields), so nothing needs to be mounted.
//
//	pass_hash = SHA256(SHA256(UTF16LE(password)))
//	buf = updateHash[32]=0 || pass_hash[32] || salt[16] || counter[8 LE]
//	repeat 1048576×: buf[0:32] = SHA256(buf)     (counter = iteration index)
//	aes_key = buf[0:32]
//
// Accepted format ($bitlocker$ … as produced by bitlocker2smith-style tools):
//
//	$bitlocker$<type>$<saltlen>$<salt>$<iter>$<ivlen>$<iv>$<datalen>$<data>

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// verifyBitLocker checks a passphrase against a $bitlocker$ target.
func verifyBitLocker(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$bitlocker$") {
		return false, errors.New("invalid bitlocker hash (missing $bitlocker$ prefix)")
	}
	f := strings.Split(targetHash[len("$bitlocker$"):], "$")
	// f: [type, saltlen, salt, iter, ivlen, iv, datalen, data]
	if len(f) < 8 {
		return false, errors.New("invalid bitlocker hash (need type$slen$salt$iter$ivlen$iv$dlen$data)")
	}
	salt, err := hex.DecodeString(f[2])
	if err != nil || len(salt) != 16 {
		return false, errors.New("invalid bitlocker salt (need 16 bytes)")
	}
	iter, err := strconv.Atoi(f[3])
	if err != nil || iter < 1 {
		return false, errors.New("invalid bitlocker iteration count")
	}
	iv, err := hex.DecodeString(f[5])
	if err != nil || len(iv) != 12 {
		return false, errors.New("invalid bitlocker IV (need 12 bytes)")
	}
	data, err := hex.DecodeString(f[7])
	if err != nil || len(data) < 32 {
		return false, errors.New("invalid bitlocker data")
	}

	key := bitlockerStretch(candidate, salt, iter)
	dec, err := bitlockerCTRDecrypt(key, iv, data)
	if err != nil {
		return false, err
	}
	return bitlockerVMKValid(dec), nil
}

// bitlockerStretch runs the 1,048,576-iteration SHA-256 key-stretch chain.
func bitlockerStretch(password string, salt []byte, iter int) []byte {
	passHash := sha256.Sum256(utf16le(password))
	passHash = sha256.Sum256(passHash[:])

	// 88-byte buffer: updateHash[0:32] | passHash[32:64] | salt[64:80] | counter[80:88].
	var buf [88]byte
	copy(buf[32:64], passHash[:])
	copy(buf[64:80], salt)
	for i := 0; i < iter; i++ {
		binary.LittleEndian.PutUint64(buf[80:88], uint64(i))
		h := sha256.Sum256(buf[:])
		copy(buf[0:32], h[:])
	}
	out := make([]byte, 32)
	copy(out, buf[0:32])
	return out
}

// bitlockerCTRDecrypt decrypts data with AES-CTR. The counter block is
// 0x02 || IV(12) || 0x00 0x00 0x00, with only the final byte incrementing per
// 16-byte block.
func bitlockerCTRDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var ctr [16]byte
	ctr[0] = 0x02
	copy(ctr[1:13], iv)
	// ctr[13:16] stay zero.

	out := make([]byte, len(data))
	stream := make([]byte, 16)
	for off := 0; off < len(data); off += 16 {
		block.Encrypt(stream, ctr[:])
		for i := 0; i < 16 && off+i < len(data); i++ {
			out[off+i] = data[off+i] ^ stream[i]
		}
		ctr[15]++
	}
	return out, nil
}

// bitlockerVMKValid checks the fixed structure fields of a decrypted VMK:
// size 0x2c at [16], version 0x01 at [20], key-type ≤ 0x05 at [24], 0x20 at [25].
func bitlockerVMKValid(dec []byte) bool {
	if len(dec) < 26 {
		return false
	}
	return dec[16] == 0x2c && dec[17] == 0x00 &&
		dec[20] == 0x01 && dec[21] == 0x00 &&
		dec[24] <= 0x05 && dec[25] == 0x20
}
