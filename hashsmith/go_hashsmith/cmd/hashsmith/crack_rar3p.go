package main

// RAR3 with -p (file data encrypted, header in the clear) — Hashcat 23700.
//
//	$RAR3$*1*<salt>*<crc32>*<pack size>*<unpack size>*<flags>*<data>*<method>
//
// The -hp form that crack.go already handles hides the archive header and is
// proven by a fixed marker in it. The -p form leaves the header readable and
// encrypts only the file, so there is no marker — the proof is the file's own
// CRC-32, which the header states in the clear.
//
// Only the stored method (0x30) is supported: anything else has been through
// RAR's compressor, and checking the CRC would mean implementing that too.
// A record naming a compressed method is refused rather than silently failing
// every password.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"strconv"
	"strings"
)

// rar3MethodStored is RAR's "no compression" method byte.
const rar3MethodStored = 0x30

func verifyRAR3p(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$RAR3$*1*") {
		return false, errors.New("not a RAR3 -p record")
	}
	f := strings.Split(strings.TrimPrefix(t, "$RAR3$*"), "*")
	if len(f) != 8 {
		return false, errors.New("RAR3 -p record must have 8 fields")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil || len(salt) != 8 {
		return false, errors.New("RAR3 salt must be 8 hex-encoded bytes")
	}
	// The CRC is written as raw bytes in RAR's own order, which is
	// little-endian — reading the field as a hex NUMBER gives the value
	// byte-reversed and rejects every password.
	crcBytes, err := hex.DecodeString(f[2])
	if err != nil || len(crcBytes) != 4 {
		return false, errors.New("RAR3 CRC must be 4 hex-encoded bytes")
	}
	crcVal := binary.LittleEndian.Uint32(crcBytes)
	packSize, err1 := strconv.Atoi(f[3])
	unpackSize, err2 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil || packSize < aes.BlockSize || unpackSize < 1 || unpackSize > packSize {
		return false, errors.New("RAR3 pack/unpack sizes are not a plausible pair")
	}
	if packSize%aes.BlockSize != 0 {
		return false, errors.New("RAR3 packed size is not a whole number of AES blocks")
	}
	method, err := strconv.ParseUint(f[7], 16, 8)
	if err != nil {
		return false, errors.New("RAR3 method is not hex")
	}
	if method != rar3MethodStored {
		return false, errors.New("RAR3 -p with compression is not supported; only stored (0x30) files can be checked by CRC")
	}
	data, err := hex.DecodeString(f[6])
	if err != nil || len(data) != packSize {
		return false, errors.New("RAR3 data does not match the declared packed size")
	}

	key, iv := rar3DeriveKeyIV(candidate, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, packSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)
	return crc32.ChecksumIEEE(plain[:unpackSize]) == crcVal, nil
}
