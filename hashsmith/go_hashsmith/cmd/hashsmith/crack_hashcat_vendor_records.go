package main

// Additional vendor/application records derived from Hashcat's reference
// modules. These formats do not fit the generic digest:salt machinery.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

func verifyTelegramPasscode(target, candidate string) (bool, error) {
	parts := strings.Split(target, "*")
	if len(parts) != 3 || parts[0] != "$telegram$0" || len(parts[1]) != 64 || !isHex(parts[1]) ||
		len(parts[2]) != 32 || !isHex(parts[2]) {
		return false, errors.New("invalid Telegram passcode record")
	}
	salt, _ := hex.DecodeString(parts[2])
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[1]), nil
}

func verifyMSSNTP(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "sntp-ms" || len(parts[2]) != 32 || !isHex(parts[2]) ||
		len(parts[3]) != 96 || !isHex(parts[3]) {
		return false, errors.New("invalid Microsoft SNTP record")
	}
	salt, _ := hex.DecodeString(parts[3])
	nt := md4.New()
	_, _ = nt.Write(utf16le(candidate))
	h := md5.New()
	_, _ = h.Write(nt.Sum(nil))
	_, _ = h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[2]), nil
}

func verifyCitrixPBKDF2(target, candidate string) (bool, error) {
	if len(target) != 129 || target[0] != '5' || !isHex(target[1:]) {
		return false, errors.New("invalid Citrix NetScaler PBKDF2 record")
	}
	salt, _ := hex.DecodeString(target[1:65])
	want, _ := hex.DecodeString(target[65:])
	got := pbkdf2.Key([]byte(candidate), salt, 2500, sha256.Size, sha256.New)
	return bytesEqualCT(got, want), nil
}

func verifyPasslibBcryptSHA256(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "bcrypt-sha256" ||
		!strings.HasPrefix(parts[2], "v=2,t=2") || len(parts[3]) != 22 || len(parts[4]) != 31 {
		return false, errors.New("invalid Passlib bcrypt-SHA256 record")
	}
	attrs := strings.Split(parts[2], ",")
	if len(attrs) != 3 || attrs[0] != "v=2" || len(attrs[1]) != 4 || attrs[1][:2] != "t=" ||
		(attrs[1][2:] != "2a" && attrs[1][2:] != "2b") || !strings.HasPrefix(attrs[2], "r=") {
		return false, errors.New("unsupported Passlib bcrypt-SHA256 parameters")
	}
	cost, err := strconv.Atoi(strings.TrimPrefix(attrs[2], "r="))
	if err != nil || cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return false, errors.New("invalid Passlib bcrypt-SHA256 cost")
	}
	mac := hmac.New(sha256.New, []byte(parts[3]))
	_, _ = mac.Write([]byte(candidate))
	encoded := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	bcryptRecord := "$" + attrs[1][2:] + "$" + strconv.Itoa(cost) + "$" + parts[3] + parts[4]
	if cost < 10 {
		bcryptRecord = "$" + attrs[1][2:] + "$0" + strconv.Itoa(cost) + "$" + parts[3] + parts[4]
	}
	return bcrypt.CompareHashAndPassword([]byte(bcryptRecord), []byte(encoded)) == nil, nil
}

var anopeSHA256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func anopeSHA256Block(state *[8]uint32, block []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}
	for i := 16; i < 64; i++ {
		s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ w[i-15]>>3
		s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ w[i-2]>>10
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d := state[0], state[1], state[2], state[3]
	e, f, g, h := state[4], state[5], state[6], state[7]
	for i := 0; i < 64; i++ {
		s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		ch := e&f ^ (^e)&g
		t1 := h + s1 + ch + anopeSHA256K[i] + w[i]
		s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		maj := a&b ^ a&c ^ b&c
		t2 := s0 + maj
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
	state[5] += f
	state[6] += g
	state[7] += h
}

func anopeSHA256FromState(state [8]uint32, data []byte) [sha256.Size]byte {
	paddedLen := (len(data) + 9 + 63) &^ 63
	padded := make([]byte, paddedLen)
	copy(padded, data)
	padded[len(data)] = 0x80
	binary.BigEndian.PutUint64(padded[len(padded)-8:], uint64(len(data))*8)
	for offset := 0; offset < len(padded); offset += sha256.BlockSize {
		anopeSHA256Block(&state, padded[offset:offset+sha256.BlockSize])
	}
	var out [sha256.Size]byte
	for i, value := range state {
		binary.BigEndian.PutUint32(out[i*4:], value)
	}
	return out
}

func verifyAnopeSHA256(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 3 || parts[0] != "sha256" || len(parts[1]) != 64 || !isHex(parts[1]) ||
		len(parts[2]) != 64 || !isHex(parts[2]) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Anope enc_sha256 record")
	}
	var state [8]uint32
	for i := range state {
		value, _ := strconv.ParseUint(parts[2][i*8:i*8+8], 16, 32)
		state[i] = uint32(value)
	}
	got := anopeSHA256FromState(state, []byte(candidate))
	return strings.EqualFold(hex.EncodeToString(got[:]), parts[1]), nil
}
