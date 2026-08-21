package main

import (
	"bytes"
	"encoding/ascii85"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"html"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
)

func runDecode(args []string) error {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
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
		r, err := decodeText(in, *typ, *shift, *key, *rails)
		if err != nil {
			return err
		}
		results = append(results, r)
	}
	return outputResult(strings.Join(results, "\n"), *outFile, *copyResult)
}

func decodeText(text string, typ string, shift int, key string, rails int) (string, error) {
	t := canonicalCodecType(typ)
	switch t {
	case "base64", "base64raw":
		b, err := decodeBase64Flexible(text, false)
		if err != nil {
			return "", errors.New("invalid Base64 format provided")
		}
		return string(b), nil
	case "base64url", "base64url-padded":
		b, err := decodeBase64Flexible(text, true)
		if err != nil {
			return "", errors.New("invalid Base64URL format provided")
		}
		return string(b), nil
	case "base64-mime":
		b, err := decodeBase64Flexible(text, false)
		if err != nil {
			return "", errors.New("invalid MIME Base64 format provided")
		}
		return string(b), nil
	case "base32", "base32-nopad":
		b, err := decodeBase32Flexible(text, false)
		if err != nil {
			return "", errors.New("invalid Base32 format provided")
		}
		return string(b), nil
	case "base32hex":
		b, err := decodeBase32Flexible(text, true)
		if err != nil {
			return "", errors.New("invalid Base32hex format provided")
		}
		return string(b), nil
	case "zbase32":
		b, err := decodeZBase32(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "base32crockford":
		b, err := decodeCrockford(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "base36":
		b, err := decodeBase36(text)
		if err != nil {
			return "", errors.New("invalid Base36 format provided")
		}
		return string(b), nil
	case "base45":
		b, err := decodeBase45(text)
		if err != nil {
			return "", errors.New("invalid Base45 format provided")
		}
		return string(b), nil
	case "base85", "adobe85":
		value := compactASCIIWhitespace(text)
		if strings.HasPrefix(value, "<~") && strings.HasSuffix(value, "~>") {
			value = value[2 : len(value)-2]
		}
		dst := make([]byte, len(value))
		n, _, err := ascii85.Decode(dst, []byte(value), true)
		if err != nil {
			return "", errors.New("invalid Base85 format provided")
		}
		return string(dst[:n]), nil
	case "z85":
		b, err := decodeZ85(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "base91":
		b, err := decodeBase91(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "quoted-printable":
		r := quotedprintable.NewReader(strings.NewReader(text))
		b, err := io.ReadAll(r)
		if err != nil {
			return "", errors.New("invalid Quoted-printable format provided")
		}
		return string(b), nil
	case "html-entities":
		return html.UnescapeString(text), nil
	case "uu":
		b, err := uuDecode(text)
		if err != nil {
			return "", errors.New("invalid Uuencoding format provided")
		}
		return string(b), nil
	case "base58":
		b, err := decodeBase58(text)
		if err != nil {
			return "", errors.New("invalid Base58 format provided")
		}
		return string(b), nil
	case "base58flickr":
		b, err := decodeBase58WithAlphabet(text, flickrBase58Alphabet)
		if err != nil {
			return "", errors.New("invalid Flickr Base58 format provided")
		}
		return string(b), nil
	case "base58ripple":
		b, err := decodeBase58WithAlphabet(text, rippleBase58Alphabet)
		if err != nil {
			return "", errors.New("invalid Ripple Base58 format provided")
		}
		return string(b), nil
	case "base58check":
		b, err := decodeBase58Check(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "base62":
		b, err := decodeBase62(text)
		if err != nil {
			return "", errors.New("invalid Base62 format provided")
		}
		return string(b), nil
	case "pem":
		b, err := decodePEM(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "bech32", "bech32m":
		b, _, err := decodeBech32(text, key, t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "gzip", "zlib":
		b, err := decodeCompressed(text, t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "bubblebabble":
		b, err := decodeBubbleBabble(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "nato":
		return decodeNATO(text), nil
	case "hex":
		b, err := decodeCleanHex(text)
		if err != nil {
			return "", errors.New("invalid Hex format provided")
		}
		return string(b), nil
	case "hex-escape":
		b, err := decodeHexEscape(text)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "binary":
		fields := strings.Fields(text)
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.ParseUint(f, 2, 8)
			if err != nil {
				return "", errors.New("invalid Binary format provided")
			}
			out = append(out, byte(v))
		}
		return string(out), nil
	case "decimal":
		fields := strings.Fields(text)
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.Atoi(f)
			if err != nil || v < 0 || v > 255 {
				return "", errors.New("invalid Decimal format provided")
			}
			out = append(out, byte(v))
		}
		return string(out), nil
	case "octal":
		fields := strings.Fields(text)
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.ParseUint(f, 8, 8)
			if err != nil {
				return "", errors.New("invalid Octal format provided")
			}
			out = append(out, byte(v))
		}
		return string(out), nil
	case "morse":
		return decodeMorse(text), nil
	case "url":
		return decodeURL(text), nil
	case "url-form":
		return formURLDecode(text)
	case "json":
		return jsonEscapeDecode(text)
	case "caesar":
		return caesar(text, -shift), nil
	case "rot13":
		return caesar(text, 13), nil
	case "rot5":
		return rot5(text), nil
	case "rot18":
		return rot18(text), nil
	case "rot47":
		return rot47(text), nil
	case "vigenere":
		return vigenereDecode(text, key)
	case "xor":
		return xorDecode(text, key)
	case "atbash":
		return atbash(text), nil
	case "baconian":
		return baconianDecode(text)
	case "leet":
		return leetDecode(text), nil
	case "reverse":
		return reverse(text), nil
	case "brainf*ck":
		return brainfuckDecode(text)
	case "railfence":
		return railFenceDecode(text, rails)
	case "polybius":
		return polybiusDecode(text)
	case "a1z26":
		return a1z26Decode(text)
	case "unicode":
		return unicodeEscapeDecode(text)
	case "utf16le":
		return decodeUTF16Hex(text, binary.LittleEndian)
	case "utf16be":
		return decodeUTF16Hex(text, binary.BigEndian)
	case "utf32le":
		return decodeUTF32Hex(text, binary.LittleEndian)
	case "utf32be":
		return decodeUTF32Hex(text, binary.BigEndian)
	default:
		return "", errors.New("unsupported decode type")
	}
}

func decodeBase62(text string) ([]byte, error) {
	if text == "" {
		return []byte{}, nil
	}
	num := big.NewInt(0)
	base := big.NewInt(62)
	for _, ch := range text {
		idx := strings.IndexRune(base62Alphabet, ch)
		if idx < 0 {
			return nil, errors.New("invalid")
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	out := num.Bytes()
	pad := 0
	for _, ch := range text {
		if ch == '0' {
			pad++
		} else {
			break
		}
	}
	if pad > 0 {
		out = append(bytes.Repeat([]byte{0}, pad), out...)
	}
	return out, nil
}

// decodeNATO converts a NATO phonetic alphabet string back to plain text.
// Tokens are split on whitespace and commas; "/" is treated as a space marker.
// Each token is looked up case-insensitively as-is first (so "X-ray" matches
// the entry "x-ray" before any dash-splitting is attempted).  Only when a
// whole-token match fails is the token split on dashes, enabling inputs like
// "Alpha-Bravo-Charlie" to decode correctly.
func decodeNATO(text string) string {
	cleaned := strings.ReplaceAll(text, ",", " ")
	tokens := strings.Fields(cleaned)
	var out strings.Builder
	for _, t := range tokens {
		if t == "/" {
			out.WriteByte(' ')
			continue
		}
		// Try the token whole first — handles "X-ray", "x-ray", "X-RAY".
		if ch, ok := reverseNATO[strings.ToLower(t)]; ok {
			out.WriteRune(ch)
			continue
		}
		// Fall back: split on dashes — handles "Alpha-Bravo-Charlie" style.
		for _, part := range strings.Split(t, "-") {
			if part == "" {
				continue
			}
			if ch, ok := reverseNATO[strings.ToLower(part)]; ok {
				out.WriteRune(ch)
			}
		}
	}
	return out.String()
}

func decodeBase58(text string) ([]byte, error) {
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, ch := range text {
		idx := strings.IndexRune(base58Alphabet, ch)
		if idx < 0 {
			return nil, errors.New("invalid")
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	out := num.Bytes()
	pad := 0
	for _, ch := range text {
		if ch == '1' {
			pad++
		} else {
			break
		}
	}
	if pad > 0 {
		out = append(bytes.Repeat([]byte{0}, pad), out...)
	}
	return out, nil
}

func decodeMorse(text string) string {
	tokens := strings.Fields(strings.TrimSpace(text))
	var b strings.Builder
	for _, t := range tokens {
		if ch, ok := reverseMorse[t]; ok {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func decodeURL(text string) string {
	v, err := url.QueryUnescape(strings.ReplaceAll(text, "+", "%2B"))
	if err != nil {
		return text
	}
	return v
}

func vigenereDecode(text string, key string) (string, error) {
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
				out = append(out, rune((int(ch-'a')-shift+26)%26+'a'))
			} else {
				out = append(out, rune((int(ch-'A')-shift+26)%26+'A'))
			}
			ki++
		} else {
			out = append(out, ch)
		}
	}
	return string(out), nil
}

func xorDecode(text string, key string) (string, error) {
	if key == "" {
		return "", errors.New("XOR key is required")
	}
	data, err := hex.DecodeString(text)
	if err != nil {
		return "", errors.New("invalid XOR hex format provided")
	}
	k := []byte(key)
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ k[i%len(k)]
	}
	return string(out), nil
}

func baconianDecode(text string) (string, error) {
	tokens := strings.Fields(strings.TrimSpace(text))
	out := []rune{}
	for _, t := range tokens {
		if t == "/" {
			out = append(out, ' ')
			continue
		}
		if len(t) != 5 {
			return "", errors.New("invalid Baconian format provided")
		}
		val := 0
		for _, ch := range strings.ToUpper(t) {
			if ch == 'B' {
				val = (val << 1) | 1
			} else if ch == 'A' {
				val = val << 1
			} else {
				return "", errors.New("invalid Baconian format provided")
			}
		}
		if val < 0 || val > 25 {
			return "", errors.New("invalid Baconian format provided")
		}
		out = append(out, rune('A'+val))
	}
	return string(out), nil
}

func leetDecode(text string) string {
	m := map[rune]rune{'0': 'O', '1': 'I', '3': 'E', '4': 'A', '5': 'S', '7': 'T'}
	out := []rune{}
	for _, ch := range text {
		if v, ok := m[ch]; ok {
			out = append(out, v)
		} else {
			out = append(out, ch)
		}
	}
	return string(out)
}

func brainfuckDecode(code string) (string, error) {
	valid := "+-<>[],."
	for _, ch := range code {
		if !strings.ContainsRune(valid, ch) {
			return "", errors.New("invalid Brainfuck format provided")
		}
	}
	tape := []byte{0}
	ptr := 0
	out := make([]byte, 0)
	pairs := map[int]int{}
	stack := []int{}
	for i, ch := range code {
		if ch == '[' {
			stack = append(stack, i)
		} else if ch == ']' {
			if len(stack) == 0 {
				return "", errors.New("invalid Brainfuck format provided")
			}
			j := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			pairs[i] = j
			pairs[j] = i
		}
	}
	if len(stack) != 0 {
		return "", errors.New("invalid Brainfuck format provided")
	}
	for i := 0; i < len(code); i++ {
		ch := code[i]
		switch ch {
		case '+':
			tape[ptr]++
		case '-':
			tape[ptr]--
		case '>':
			ptr++
			if ptr == len(tape) {
				tape = append(tape, 0)
			}
		case '<':
			ptr--
			if ptr < 0 {
				return "", errors.New("invalid Brainfuck format provided")
			}
		case '.':
			out = append(out, tape[ptr])
		case ',':
			tape[ptr] = 0
		case '[':
			if tape[ptr] == 0 {
				i = pairs[i]
			}
		case ']':
			if tape[ptr] != 0 {
				i = pairs[i]
			}
		}
	}
	return string(out), nil
}

func railFenceDecode(text string, rails int) (string, error) {
	if rails < 2 {
		return "", errors.New("Rails must be >= 2")
	}
	n := len([]rune(text))
	pattern := make([]int, n)
	rail := 0
	dir := 1
	for i := 0; i < n; i++ {
		pattern[i] = rail
		rail += dir
		if rail == 0 || rail == rails-1 {
			dir *= -1
		}
	}
	counts := make([]int, rails)
	for _, r := range pattern {
		counts[r]++
	}
	runes := []rune(text)
	railsData := make([][]rune, rails)
	idx := 0
	for r := 0; r < rails; r++ {
		railsData[r] = append([]rune{}, runes[idx:idx+counts[r]]...)
		idx += counts[r]
	}
	pos := make([]int, rails)
	out := make([]rune, 0, n)
	for _, r := range pattern {
		out = append(out, railsData[r][pos[r]])
		pos[r]++
	}
	return string(out), nil
}

func polybiusDecode(text string) (string, error) {
	alphabet := "ABCDEFGHIKLMNOPQRSTUVWXYZ"
	tokens := strings.Fields(strings.TrimSpace(text))
	out := []rune{}
	for _, t := range tokens {
		if t == "/" {
			out = append(out, ' ')
			continue
		}
		if len(t) != 2 {
			return "", errors.New("invalid Polybius format provided")
		}
		row := int(t[0] - '1')
		col := int(t[1] - '1')
		if row < 0 || row >= 5 || col < 0 || col >= 5 {
			return "", errors.New("invalid Polybius format provided")
		}
		out = append(out, rune(alphabet[row*5+col]))
	}
	return string(out), nil
}

func unicodeEscapeDecode(text string) (string, error) {
	if len(text)%6 != 0 {
		return "", errors.New("invalid Unicode escaped format provided")
	}
	units := make([]uint16, 0, len(text)/6)
	for i := 0; i < len(text); i += 6 {
		chunk := text[i : i+6]
		if !strings.HasPrefix(chunk, "\\u") {
			return "", errors.New("invalid Unicode escaped format provided")
		}
		v, err := strconv.ParseUint(chunk[2:], 16, 16)
		if err != nil {
			return "", errors.New("invalid Unicode escaped format provided")
		}
		units = append(units, uint16(v))
	}
	if !validUTF16(units) {
		return "", errors.New("invalid Unicode surrogate sequence provided")
	}
	return string(utf16.Decode(units)), nil
}

func uuDecode(text string) ([]byte, error) {
	if strings.TrimSpace(text) == "" {
		return []byte{}, nil
	}
	var out []byte
	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) < 1 {
			return nil, errors.New("invalid")
		}
		n := int((line[0] - 32) & 0x3F)
		body := []byte(line[1:])
		decoded := make([]byte, 0, n)
		for i := 0; i < len(body); i += 4 {
			if i+4 > len(body) {
				return nil, errors.New("invalid")
			}
			c1 := body[i]
			c2 := body[i+1]
			c3 := body[i+2]
			c4 := body[i+3]
			if c1 == '`' {
				c1 = ' '
			}
			if c2 == '`' {
				c2 = ' '
			}
			if c3 == '`' {
				c3 = ' '
			}
			if c4 == '`' {
				c4 = ' '
			}
			v1 := (c1 - 32) & 0x3F
			v2 := (c2 - 32) & 0x3F
			v3 := (c3 - 32) & 0x3F
			v4 := (c4 - 32) & 0x3F
			b1 := (v1 << 2) | (v2 >> 4)
			b2 := (v2 << 4) | (v3 >> 2)
			b3 := (v3 << 6) | v4
			decoded = append(decoded, b1, b2, b3)
		}
		if n > len(decoded) {
			return nil, errors.New("invalid")
		}
		out = append(out, decoded[:n]...)
	}
	return out, nil
}
