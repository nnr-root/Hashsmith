package main

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math/big"
	"mime/quotedprintable"
	"strconv"
	"strings"
)

func runEncode(args []string) error {
	fs := flag.NewFlagSet("encode", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "type")
	outFile := fs.String("o", "", "output file")
	copyResult := fs.Bool("c", false, "copy to clipboard")
	shift := fs.Int("s", 3, "shift")
	key := fs.String("k", "", "key")
	rails := fs.Int("r", 2, "rails")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	inputs, err := gatherInputs(fs.Args())
	if err != nil {
		return err
	}
	results := make([]string, 0, len(inputs))
	for _, in := range inputs {
		r, err := encodeText(in, *typ, *shift, *key, *rails)
		if err != nil {
			return err
		}
		results = append(results, r)
	}
	return outputResult(strings.Join(results, "\n"), *outFile, *copyResult)
}

func encodeText(text string, typ string, shift int, key string, rails int) (string, error) {
	t := strings.ToLower(typ)
	switch t {
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(text)), nil
	case "base64url":
		return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(text)), "="), nil
	case "base32":
		return base32.StdEncoding.EncodeToString([]byte(text)), nil
	case "base85":
		out := make([]byte, ascii85.MaxEncodedLen(len(text)))
		n := ascii85.Encode(out, []byte(text))
		return string(out[:n]), nil
	case "quoted-printable":
		var buf bytes.Buffer
		w := quotedprintable.NewWriter(&buf)
		_, _ = w.Write([]byte(text))
		_ = w.Close()
		return buf.String(), nil
	case "html-entities":
		return html.EscapeString(text), nil
	case "uu":
		return uuEncode([]byte(text)), nil
	case "base58":
		return encodeBase58([]byte(text)), nil
	case "base62":
		return encodeBase62([]byte(text)), nil
	case "nato":
		return encodeNATO(text), nil
	case "hex":
		return hex.EncodeToString([]byte(text)), nil
	case "binary":
		out := make([]string, 0, len(text))
		for _, b := range []byte(text) {
			out = append(out, fmt.Sprintf("%08b", b))
		}
		return strings.Join(out, " "), nil
	case "decimal":
		out := make([]string, 0, len(text))
		for _, b := range []byte(text) {
			out = append(out, strconv.Itoa(int(b)))
		}
		return strings.Join(out, " "), nil
	case "octal":
		out := make([]string, 0, len(text))
		for _, b := range []byte(text) {
			out = append(out, strconv.FormatInt(int64(b), 8))
		}
		return strings.Join(out, " "), nil
	case "morse":
		return encodeMorse(text), nil
	case "url":
		return encodeURL(text), nil
	case "caesar":
		return caesar(text, shift), nil
	case "rot13":
		return caesar(text, 13), nil
	case "vigenere":
		return vigenereEncode(text, key)
	case "xor":
		return xorEncode(text, key)
	case "atbash":
		return atbash(text), nil
	case "baconian":
		return baconianEncode(text), nil
	case "leet":
		return leetEncode(text), nil
	case "reverse":
		return reverse(text), nil
	case "brainf*ck":
		return brainfuckEncode(text), nil
	case "railfence":
		return railFenceEncode(text, rails)
	case "polybius":
		return polybiusEncode(text), nil
	case "unicode":
		return unicodeEscapeEncode(text), nil
	default:
		return "", errors.New("unsupported encode type")
	}
}

func encodeBase62(data []byte) string {
	if len(data) == 0 {
		return "0"
	}
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(62)
	zero := big.NewInt(0)
	rem := new(big.Int)
	out := make([]byte, 0)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, rem)
		out = append(out, base62Alphabet[rem.Int64()])
	}
	for _, b := range data {
		if b == 0 {
			out = append(out, '0')
		} else {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func encodeNATO(text string) string {
	out := make([]string, 0, len(text))
	for _, ch := range strings.ToUpper(text) {
		if word, ok := natoAlphabet[ch]; ok {
			out = append(out, word)
		} else if ch == ' ' {
			out = append(out, "/")
		}
	}
	return strings.Join(out, " ")
}

func encodeBase58(data []byte) string {
	if len(data) == 0 {
		return "1"
	}
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	rem := new(big.Int)
	out := make([]byte, 0)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, rem)
		out = append(out, base58Alphabet[rem.Int64()])
	}
	for _, b := range data {
		if b == 0 {
			out = append(out, '1')
		} else {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func encodeMorse(text string) string {
	out := []string{}
	for _, ch := range strings.ToUpper(text) {
		if code, ok := morseMap[ch]; ok {
			out = append(out, code)
		}
	}
	return strings.Join(out, " ")
}

func encodeURL(text string) string {
	var b strings.Builder
	for _, c := range []byte(text) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func caesar(text string, shift int) string {
	shift = ((shift % 26) + 26) % 26
	out := make([]rune, 0, len(text))
	for _, ch := range text {
		if ch >= 'a' && ch <= 'z' {
			out = append(out, rune((int(ch-'a')+shift)%26+'a'))
		} else if ch >= 'A' && ch <= 'Z' {
			out = append(out, rune((int(ch-'A')+shift)%26+'A'))
		} else {
			out = append(out, ch)
		}
	}
	return string(out)
}

func vigenereEncode(text string, key string) (string, error) {
	if key == "" {
		return "", errors.New("Vigenere key must be alphabetic")
	}
	for _, ch := range key {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			return "", errors.New("Vigenere key must be alphabetic")
		}
	}
	key = strings.ToLower(key)
	out := []rune{}
	ki := 0
	for _, ch := range text {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			shift := int(key[ki%len(key)] - 'a')
			if ch >= 'a' && ch <= 'z' {
				out = append(out, rune((int(ch-'a')+shift)%26+'a'))
			} else {
				out = append(out, rune((int(ch-'A')+shift)%26+'A'))
			}
			ki++
		} else {
			out = append(out, ch)
		}
	}
	return string(out), nil
}

func xorEncode(text string, key string) (string, error) {
	if key == "" {
		return "", errors.New("XOR key is required")
	}
	data := []byte(text)
	k := []byte(key)
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ k[i%len(k)]
	}
	return hex.EncodeToString(out), nil
}

func atbash(text string) string {
	out := []rune{}
	for _, ch := range text {
		if ch >= 'a' && ch <= 'z' {
			out = append(out, rune('z'-(ch-'a')))
		} else if ch >= 'A' && ch <= 'Z' {
			out = append(out, rune('Z'-(ch-'A')))
		} else {
			out = append(out, ch)
		}
	}
	return string(out)
}

func baconianEncode(text string) string {
	tokens := []string{}
	for _, ch := range text {
		if ch == ' ' {
			tokens = append(tokens, "/")
			continue
		}
		u := ch
		if ch >= 'a' && ch <= 'z' {
			u = ch - 32
		}
		if u >= 'A' && u <= 'Z' {
			idx := int(u - 'A')
			var b strings.Builder
			for bit := 4; bit >= 0; bit-- {
				if (idx>>bit)&1 == 1 {
					b.WriteByte('B')
				} else {
					b.WriteByte('A')
				}
			}
			tokens = append(tokens, b.String())
		}
	}
	return strings.Join(tokens, " ")
}

func leetEncode(text string) string {
	m := map[rune]rune{'A': '4', 'E': '3', 'S': '5', 'T': '7', 'O': '0'}
	out := []rune{}
	for _, ch := range text {
		u := ch
		if ch >= 'a' && ch <= 'z' {
			u = ch - 32
		}
		if v, ok := m[u]; ok {
			out = append(out, v)
		} else {
			out = append(out, ch)
		}
	}
	return string(out)
}

func reverse(text string) string {
	runes := []rune(text)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func brainfuckEncode(text string) string {
	cur := 0
	var out strings.Builder
	for _, ch := range text {
		t := int(ch)
		delta := t - cur
		if delta > 0 {
			out.WriteString(strings.Repeat("+", delta))
		} else if delta < 0 {
			out.WriteString(strings.Repeat("-", -delta))
		}
		out.WriteByte('.')
		cur = t
	}
	return out.String()
}

func railFenceEncode(text string, rails int) (string, error) {
	if rails < 2 {
		return "", errors.New("Rails must be >= 2")
	}
	fence := make([][]rune, rails)
	rail := 0
	dir := 1
	for _, ch := range text {
		fence[rail] = append(fence[rail], ch)
		rail += dir
		if rail == 0 || rail == rails-1 {
			dir *= -1
		}
	}
	var out strings.Builder
	for _, row := range fence {
		out.WriteString(string(row))
	}
	return out.String(), nil
}

func polybiusEncode(text string) string {
	alphabet := "ABCDEFGHIKLMNOPQRSTUVWXYZ"
	out := []string{}
	for _, ch := range strings.ToUpper(text) {
		if ch == 'J' {
			ch = 'I'
		}
		if ch == ' ' {
			out = append(out, "/")
			continue
		}
		idx := strings.IndexRune(alphabet, ch)
		if idx >= 0 {
			row := idx/5 + 1
			col := idx%5 + 1
			out = append(out, fmt.Sprintf("%d%d", row, col))
		}
	}
	return strings.Join(out, " ")
}

func unicodeEscapeEncode(text string) string {
	var out strings.Builder
	for _, ch := range text {
		out.WriteString(fmt.Sprintf("\\u%04x", ch))
	}
	return out.String()
}

func uuEncode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	lines := []string{}
	for i := 0; i < len(data); i += 45 {
		end := i + 45
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		line := make([]byte, 0, 1+((len(chunk)+2)/3)*4)
		line = append(line, byte((len(chunk)&0x3F)+32))
		for j := 0; j < len(chunk); j += 3 {
			a := chunk[j]
			var b, c byte
			if j+1 < len(chunk) {
				b = chunk[j+1]
			}
			if j+2 < len(chunk) {
				c = chunk[j+2]
			}
			vals := []byte{
				(a >> 2) & 0x3F,
				((a << 4) | (b >> 4)) & 0x3F,
				((b << 2) | (c >> 6)) & 0x3F,
				c & 0x3F,
			}
			for _, v := range vals {
				line = append(line, v+32)
			}
		}
		lines = append(lines, string(line))
	}
	return strings.Join(lines, "\n")
}
