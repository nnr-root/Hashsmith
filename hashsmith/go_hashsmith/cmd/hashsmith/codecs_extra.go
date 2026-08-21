package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	maxDecodedSize    = 64 << 20
)

func encodeCrockford(data []byte) string {
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
			out.WriteByte(crockfordAlphabet[(acc>>bits)&31])
		}
		if bits > 0 {
			acc &= (1 << bits) - 1
		} else {
			acc = 0
		}
	}
	if bits > 0 {
		out.WriteByte(crockfordAlphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

func decodeCrockford(text string) ([]byte, error) {
	var out []byte
	var acc uint32
	bits := 0
	for _, r := range text {
		if r == '-' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		ch := byte(r)
		if ch >= 'a' && ch <= 'z' {
			ch -= 'a' - 'A'
		}
		switch ch {
		case 'O':
			ch = '0'
		case 'I', 'L':
			ch = '1'
		}
		value := strings.IndexByte(crockfordAlphabet, ch)
		if value < 0 {
			return nil, fmt.Errorf("invalid Crockford Base32 character %q", r)
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
		return nil, errors.New("invalid non-zero Crockford Base32 padding bits")
	}
	return out, nil
}

func base58CheckSum(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return second[:4]
}

func encodeBase58Check(payload []byte) string {
	data := make([]byte, 0, len(payload)+4)
	data = append(data, payload...)
	data = append(data, base58CheckSum(payload)...)
	return encodeBase58(data)
}

func decodeBase58Check(text string) ([]byte, error) {
	data, err := decodeBase58(text)
	if err != nil || len(data) < 4 {
		return nil, errors.New("invalid Base58Check format")
	}
	payload, checksum := data[:len(data)-4], data[len(data)-4:]
	if !bytesEqualCT(base58CheckSum(payload), checksum) {
		return nil, errors.New("invalid Base58Check checksum")
	}
	return payload, nil
}

func encodeMIMEBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	if len(encoded) <= 76 {
		return encoded
	}
	var out strings.Builder
	out.Grow(len(encoded) + len(encoded)/76*2)
	for len(encoded) > 76 {
		out.WriteString(encoded[:76])
		out.WriteString("\r\n")
		encoded = encoded[76:]
	}
	out.WriteString(encoded)
	return out.String()
}

func encodePEM(data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "DATA", Bytes: data}))
}

func decodePEM(text string) ([]byte, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid PEM data")
	}
	return block.Bytes, nil
}

func isPEMData(text string) bool {
	_, err := decodePEM(text)
	return err == nil
}

func looksLikeZlib(data []byte) bool {
	return len(data) >= 2 && data[0]&0x0f == 8 && data[0]>>4 <= 7 &&
		(uint16(data[0])<<8|uint16(data[1]))%31 == 0
}

func isMIMEBase64(text string) bool {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return false
	}
	for i, line := range lines {
		if line == "" && i == len(lines)-1 {
			continue
		}
		if (i < len(lines)-1 && len(line) != 76) || len(line) > 76 {
			return false
		}
	}
	_, err := decodeBase64Flexible(text, false)
	return err == nil
}

func isCrockfordCandidate(text string) bool {
	if len(text) < 4 || !strings.ContainsAny(strings.ToUpper(text), "0189-") {
		return false
	}
	_, err := decodeCrockford(text)
	return err == nil
}

func encodeCompressed(data []byte, typ string) (string, error) {
	var buf bytes.Buffer
	var w io.WriteCloser
	var err error
	switch typ {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "zlib":
		w = zlib.NewWriter(&buf)
	default:
		return "", errors.New("unsupported compression type")
	}
	if _, err = w.Write(data); err == nil {
		err = w.Close()
	} else {
		_ = w.Close()
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func decodeCompressed(text, typ string) ([]byte, error) {
	compressed, err := decodeBase64Flexible(text, false)
	if err != nil {
		return nil, fmt.Errorf("invalid %s Base64 transport", typ)
	}
	var r io.ReadCloser
	switch typ {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(compressed))
	case "zlib":
		r, err = zlib.NewReader(bytes.NewReader(compressed))
	default:
		return nil, errors.New("unsupported compression type")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid %s stream", typ)
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxDecodedSize+1))
	if err != nil {
		return nil, fmt.Errorf("invalid %s stream", typ)
	}
	if len(data) > maxDecodedSize {
		return nil, fmt.Errorf("decoded %s data exceeds 64 MiB limit", typ)
	}
	return data, nil
}

func encodeHexEscape(data []byte) string {
	var out strings.Builder
	out.Grow(len(data) * 4)
	for _, b := range data {
		fmt.Fprintf(&out, "\\x%02x", b)
	}
	return out.String()
}

func decodeHexEscape(text string) ([]byte, error) {
	if len(text)%4 != 0 {
		return nil, errors.New("invalid hex-escape length")
	}
	out := make([]byte, 0, len(text)/4)
	for i := 0; i < len(text); i += 4 {
		if text[i] != '\\' || (text[i+1] != 'x' && text[i+1] != 'X') {
			return nil, errors.New("invalid hex-escape sequence")
		}
		b, err := hex.DecodeString(text[i+2 : i+4])
		if err != nil {
			return nil, errors.New("invalid hex-escape byte")
		}
		out = append(out, b[0])
	}
	return out, nil
}

func rot5(text string) string {
	b := []byte(text)
	for i, ch := range b {
		if ch >= '0' && ch <= '9' {
			b[i] = '0' + (ch-'0'+5)%10
		}
	}
	return string(b)
}

func rot18(text string) string {
	return rot5(caesar(text, 13))
}
