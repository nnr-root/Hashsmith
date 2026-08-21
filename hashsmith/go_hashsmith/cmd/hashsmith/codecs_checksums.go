package main

import (
	"errors"
	"fmt"
	"strings"
)

const (
	zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	bech32Alphabet  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32Constant  = uint32(1)
	bech32mConstant = uint32(0x2bc830a3)
)

func encodeZBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var out strings.Builder
	out.Grow((len(data)*8 + 4) / 5)
	var acc uint32
	bits := 0
	for _, b := range data {
		acc = (acc << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(zBase32Alphabet[(acc>>bits)&31])
		}
		if bits > 0 {
			acc &= (1 << bits) - 1
		} else {
			acc = 0
		}
	}
	if bits > 0 {
		out.WriteByte(zBase32Alphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

func decodeZBase32(text string) ([]byte, error) {
	text = strings.ToLower(compactASCIIWhitespace(text))
	var out []byte
	var acc uint32
	bits := 0
	for _, r := range text {
		value := strings.IndexRune(zBase32Alphabet, r)
		if value < 0 {
			return nil, fmt.Errorf("invalid z-base-32 character %q", r)
		}
		acc = (acc << 5) | uint32(value)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
		if bits > 0 {
			acc &= (1 << bits) - 1
		} else {
			acc = 0
		}
	}
	if bits >= 5 || (bits > 0 && acc != 0) {
		return nil, errors.New("invalid non-zero z-base-32 padding bits")
	}
	return out, nil
}

func isZBase32Candidate(text string) bool {
	compact := strings.ToLower(compactASCIIWhitespace(text))
	if len(compact) < 4 || !strings.ContainsAny(compact, "13456789") {
		return false
	}
	decoded, err := decodeZBase32(compact)
	return err == nil && encodeZBase32(decoded) == compact
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	bits := uint(0)
	maxValue := uint32(1<<toBits) - 1
	maxAcc := uint32(1<<(fromBits+toBits-1)) - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, value := range data {
		if uint32(value)>>fromBits != 0 {
			return nil, errors.New("input value exceeds source bit width")
		}
		acc = ((acc << fromBits) | uint32(value)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxValue))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxValue))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxValue) != 0 {
		return nil, errors.New("invalid incomplete bit group")
	}
	return out, nil
}

func bech32Polymod(values []byte) uint32 {
	generators := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(value)
		for i, generator := range generators {
			if top>>i&1 != 0 {
				chk ^= generator
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := range hrp {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range hrp {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32EncodingConstant(typ string) uint32 {
	if typ == "bech32m" {
		return bech32mConstant
	}
	return bech32Constant
}

func encodeBech32(data []byte, hrp, typ string) (string, error) {
	if hrp == "" || len(hrp) > 83 {
		return "", errors.New("Bech32 requires a 1–83 character HRP (use -k)")
	}
	if hrp != strings.ToLower(hrp) && hrp != strings.ToUpper(hrp) {
		return "", errors.New("Bech32 HRP must not mix letter case")
	}
	hrp = strings.ToLower(hrp)
	for i := range hrp {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", errors.New("Bech32 HRP contains an invalid character")
		}
	}
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	checkInput := append(bech32HRPExpand(hrp), values...)
	checkInput = append(checkInput, make([]byte, 6)...)
	polymod := bech32Polymod(checkInput) ^ bech32EncodingConstant(typ)
	var out strings.Builder
	out.Grow(len(hrp) + 1 + len(values) + 6)
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, value := range values {
		out.WriteByte(bech32Alphabet[value])
	}
	for i := 0; i < 6; i++ {
		out.WriteByte(bech32Alphabet[(polymod>>uint(5*(5-i)))&31])
	}
	if out.Len() > 90 {
		return "", errors.New("Bech32 output exceeds the 90-character limit")
	}
	return out.String(), nil
}

func decodeBech32(text, expectedHRP, typ string) ([]byte, string, error) {
	if len(text) < 8 || len(text) > 90 {
		return nil, "", errors.New("invalid Bech32 length")
	}
	if text != strings.ToLower(text) && text != strings.ToUpper(text) {
		return nil, "", errors.New("Bech32 must not mix letter case")
	}
	text = strings.ToLower(text)
	separator := strings.LastIndexByte(text, '1')
	if separator < 1 || separator+7 > len(text) {
		return nil, "", errors.New("invalid Bech32 separator position")
	}
	hrp := text[:separator]
	if expectedHRP != "" && !strings.EqualFold(hrp, expectedHRP) {
		return nil, "", errors.New("Bech32 HRP does not match -k")
	}
	for i := range hrp {
		if hrp[i] < 33 || hrp[i] > 126 {
			return nil, "", errors.New("invalid Bech32 HRP character")
		}
	}
	values := make([]byte, len(text)-separator-1)
	for i := range values {
		value := strings.IndexByte(bech32Alphabet, text[separator+1+i])
		if value < 0 {
			return nil, "", errors.New("invalid Bech32 data character")
		}
		values[i] = byte(value)
	}
	checkInput := append(bech32HRPExpand(hrp), values...)
	if bech32Polymod(checkInput) != bech32EncodingConstant(typ) {
		return nil, "", errors.New("invalid Bech32 checksum")
	}
	decoded, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return nil, "", err
	}
	return decoded, hrp, nil
}

func isBech32(text, typ string) bool {
	_, _, err := decodeBech32(text, "", typ)
	return err == nil
}
