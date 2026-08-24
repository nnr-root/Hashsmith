package main

// Small, self-contained formats that close common Hashcat/John compatibility
// gaps without requiring an external container extractor.

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// ArubaOS (Hashcat 125): salt(4) || 0x01 || SHA1(salt || 0x01 || password).
func verifyArubaOS(target, candidate string) (bool, error) {
	if len(target) != 50 || !isHex(target) || !strings.EqualFold(target[8:10], "01") {
		return false, errors.New("invalid ArubaOS hash")
	}
	prefix, _ := hex.DecodeString(target[:10])
	h := sha1.New()
	_, _ = h.Write(prefix)
	_, _ = h.Write([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), target[10:]), nil
}

// Hashcat 14400: ten rounds of SHA1 over a CX framing. The digest is hex text
// between rounds, matching Hashcat's and John's interchange representation.
func verifySHA1CX(target, candidate string) (bool, error) {
	digest, salt, ok := strings.Cut(target, ":")
	if !ok || len(digest) != 40 || !isHex(digest) || len(salt) != 20 {
		return false, errors.New("invalid sha1(CX) record")
	}
	begin := "--" + salt + "--"
	end := "--" + candidate + "----"
	sum := sha1.Sum([]byte(begin + end))
	got := hex.EncodeToString(sum[:])
	for round := 1; round < 10; round++ {
		sum = sha1.Sum([]byte(begin + got + end))
		got = hex.EncodeToString(sum[:])
	}
	return strings.EqualFold(got, digest), nil
}

// Dovecot stores the MD5 chaining states after the HMAC ipad/opad blocks.
// Hashcat mode 16400 compares the first (opad) state, which is sufficient to
// recover the password and is the canonical doveadm export behavior.
func verifyDovecotCRAMMD5(target, candidate string) (bool, error) {
	const prefix = "{CRAM-MD5}"
	if !strings.HasPrefix(target, prefix) || len(target) != len(prefix)+64 || !isHex(target[len(prefix):]) {
		return false, errors.New("invalid Dovecot CRAM-MD5 record")
	}
	if len(candidate) > md5.BlockSize {
		return false, errors.New("Dovecot CRAM-MD5 passwords are limited to 64 bytes")
	}
	block := make([]byte, md5.BlockSize)
	for i := range block {
		block[i] = 0x5c
	}
	for i, b := range []byte(candidate) {
		block[i] ^= b
	}
	h := md5.New()
	_, _ = h.Write(block)
	marshaler, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return false, errors.New("MD5 state export unavailable")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil || len(state) < 20 {
		return false, errors.New("could not export MD5 state")
	}
	var raw [md5.Size]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(raw[i*4:], binary.BigEndian.Uint32(state[4+i*4:]))
	}
	return strings.EqualFold(hex.EncodeToString(raw[:]), target[len(prefix):len(prefix)+32]), nil
}
