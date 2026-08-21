package main

// Shared codec registry and implementations for the less common byte/text
// encodings. Keeping aliases here gives encode, decode, help, and tests one
// canonical vocabulary.

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	base36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	base45Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	z85Alphabet    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
	base91Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)

func canonicalCodecType(typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	t = strings.ReplaceAll(t, "_", "-")
	switch t {
	case "b16", "base16", "base-16":
		return "hex"
	case "hexadecimal":
		return "hex"
	case "b32", "base-32":
		return "base32"
	case "base32-no-padding", "base32-raw":
		return "base32-nopad"
	case "base32-hex", "base-32-hex":
		return "base32hex"
	case "zbase32", "z-base32", "z-base-32":
		return "zbase32"
	case "crockford", "crockford32", "base32-crockford", "base-32-crockford":
		return "base32crockford"
	case "base-36":
		return "base36"
	case "base-45":
		return "base45"
	case "b58", "base-58":
		return "base58"
	case "base58-flickr", "base-58-flickr", "flickr58":
		return "base58flickr"
	case "base58-ripple", "base-58-ripple", "ripple58", "xrp-base58":
		return "base58ripple"
	case "base58-check", "base-58-check", "b58check":
		return "base58check"
	case "b62", "base-62":
		return "base62"
	case "b64", "base-64":
		return "base64"
	case "base64-raw", "base-64-raw":
		return "base64raw"
	case "base64-url", "base-64-url", "base64urlsafe":
		return "base64url"
	case "base64-url-padded", "base-64-url-padded":
		return "base64url-padded"
	case "mime-base64", "base-64-mime":
		return "base64-mime"
	case "b85", "base-85", "ascii-85", "ascii85":
		return "base85"
	case "adobe-85":
		return "adobe85"
	case "b91", "base-91":
		return "base91"
	case "quotedprintable", "qp":
		return "quoted-printable"
	case "html", "htmlentities":
		return "html-entities"
	case "percent":
		return "url"
	case "urlform", "form-url", "form":
		return "url-form"
	case "json-escape", "json-string":
		return "json"
	case "c-hex", "hexescape", "hex-escapes":
		return "hex-escape"
	case "utf-16le":
		return "utf16le"
	case "utf-16be":
		return "utf16be"
	case "utf-32le":
		return "utf32le"
	case "utf-32be":
		return "utf32be"
	case "rot-13":
		return "rot13"
	case "rot-5":
		return "rot5"
	case "rot-18":
		return "rot18"
	case "rot-47":
		return "rot47"
	case "rail-fence":
		return "railfence"
	case "brainfuck", "bf":
		return "brainf*ck"
	case "a1-z26", "a1z-26":
		return "a1z26"
	case "bubble-babble", "bubblebabble":
		return "bubblebabble"
	default:
		return t
	}
}

var codecCatalogue = []typeGroup{
	{"Binary-to-text encodings", [][2]string{
		{"hex", "Hexadecimal (aliases: base16, b16)"},
		{"base32", "RFC 4648 Base32; padded or unpadded input"},
		{"base32-nopad", "Unpadded RFC 4648 Base32"},
		{"base32hex", "RFC 4648 extended-hex Base32"},
		{"zbase32", "z-base-32 human-oriented Base32"},
		{"base32crockford", "Crockford Base32 (O/I/L typo-tolerant decoding)"},
		{"base36", "Base36 big-endian byte encoding"},
		{"base45", "RFC 9285 Base45"},
		{"base58", "Bitcoin alphabet Base58"},
		{"base58flickr", "Flickr alphabet Base58"},
		{"base58ripple", "Ripple/XRP alphabet Base58"},
		{"base58check", "Base58Check with double-SHA256 checksum"},
		{"base62", "0-9/A-Z/a-z Base62"},
		{"base64", "RFC 4648 Base64; padded or unpadded input"},
		{"base64raw", "Unpadded RFC 4648 Base64"},
		{"base64url", "Unpadded URL-safe Base64"},
		{"base64url-padded", "Padded URL-safe Base64"},
		{"base64-mime", "MIME Base64 with 76-column CRLF wrapping"},
		{"base85", "ASCII85 (alias: ascii85)"},
		{"adobe85", "ASCII85 wrapped in <~ ~>"},
		{"z85", "ZeroMQ Z85 (4-byte/5-character blocks)"},
		{"base91", "basE91 compact binary-to-text encoding"},
		{"uu", "UUencoding"},
		{"pem", "PEM DATA block"},
		{"bech32 / bech32m", "Checksummed Bech32 encoding (HRP from -k)"},
		{"gzip / zlib", "Compressed data with Base64 transport"},
		{"bubblebabble", "Pronounceable Bubble Babble binary encoding"},
	}},
	{"Escaping and character encodings", [][2]string{
		{"url", "RFC 3986 percent encoding"},
		{"url-form", "Form/query encoding (spaces become +)"},
		{"html-entities", "HTML entity escaping"},
		{"json", "JSON string escaping without outer quotes"},
		{"quoted-printable", "MIME quoted-printable"},
		{"hex-escape", "C-style \\xNN byte escapes"},
		{"unicode", "Unicode \\uXXXX escapes (surrogate-pair aware)"},
		{"utf16le / utf16be", "UTF-16 represented as hexadecimal bytes"},
		{"utf32le / utf32be", "UTF-32 represented as hexadecimal bytes"},
	}},
	{"Numeric and human-readable encodings", [][2]string{
		{"binary", "8-bit binary byte groups"},
		{"decimal", "Decimal byte values"},
		{"octal", "Octal byte values"},
		{"a1z26", "A1Z26 letter-number substitution"},
		{"morse", "International Morse code"},
		{"nato", "NATO phonetic alphabet"},
	}},
	{"Classical ciphers and transforms", [][2]string{
		{"caesar", "Caesar shift (use -s)"},
		{"rot5 / rot13 / rot18 / rot47", "Fixed rotation ciphers"},
		{"vigenere", "Vigenere cipher (use -k)"},
		{"xor", "Repeating-key XOR, hex transport (use -k)"},
		{"atbash", "Atbash substitution"},
		{"baconian", "Bacon's cipher"},
		{"polybius", "Polybius square"},
		{"railfence", "Rail fence transposition (use -r)"},
		{"leet", "Leet substitutions"},
		{"reverse", "Unicode-safe reversal"},
		{"brainf*ck", "Brainfuck source generator/interpreter"},
	}},
}

func runListEncodings(_ []string) error {
	fmt.Println("Hashsmith encoding and decoding types")
	fmt.Println("Pass any of these as `encode -t <name>` or `decode -t <name>`.")
	fmt.Println()
	for _, group := range codecCatalogue {
		accentPrintln(group.title)
		for _, item := range group.items {
			fmt.Printf("  %-24s %s\n", item[0], item[1])
		}
		fmt.Println()
	}
	return nil
}

func encodeBase36(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return encodeBigRadix(data, base36Alphabet, '0')
}

func decodeBase36(text string) ([]byte, error) {
	return decodeBigRadix(strings.ToLower(text), base36Alphabet, '0')
}

func encodeBigRadix(data []byte, alphabet string, zeroDigit byte) string {
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(int64(len(alphabet)))
	zero := new(big.Int)
	rem := new(big.Int)
	out := make([]byte, 0, len(data)*2)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, rem)
		out = append(out, alphabet[rem.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = append(out, zeroDigit)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func decodeBigRadix(text, alphabet string, zeroDigit byte) ([]byte, error) {
	if text == "" {
		return []byte{}, nil
	}
	num := new(big.Int)
	base := big.NewInt(int64(len(alphabet)))
	for _, ch := range text {
		idx := strings.IndexRune(alphabet, ch)
		if idx < 0 {
			return nil, errors.New("invalid digit")
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	out := num.Bytes()
	leading := 0
	for leading < len(text) && text[leading] == zeroDigit {
		leading++
	}
	if leading > 0 {
		out = append(make([]byte, leading), out...)
	}
	return out, nil
}

func encodeBase45(data []byte) string {
	var out strings.Builder
	out.Grow((len(data)*3 + 1) / 2)
	for i := 0; i < len(data); {
		if i+1 < len(data) {
			n := int(data[i])*256 + int(data[i+1])
			out.WriteByte(base45Alphabet[n%45])
			out.WriteByte(base45Alphabet[(n/45)%45])
			out.WriteByte(base45Alphabet[n/(45*45)])
			i += 2
		} else {
			n := int(data[i])
			out.WriteByte(base45Alphabet[n%45])
			out.WriteByte(base45Alphabet[n/45])
			i++
		}
	}
	return out.String()
}

func decodeBase45(text string) ([]byte, error) {
	if len(text)%3 == 1 {
		return nil, errors.New("invalid Base45 length")
	}
	out := make([]byte, 0, len(text)*2/3+1)
	for i := 0; i < len(text); {
		remaining := len(text) - i
		group := 3
		if remaining == 2 {
			group = 2
		}
		c := make([]int, group)
		for j := range c {
			c[j] = strings.IndexByte(base45Alphabet, text[i+j])
			if c[j] < 0 {
				return nil, errors.New("invalid Base45 character")
			}
		}
		if group == 2 {
			n := c[0] + c[1]*45
			if n > 255 {
				return nil, errors.New("invalid Base45 value")
			}
			out = append(out, byte(n))
		} else {
			n := c[0] + c[1]*45 + c[2]*45*45
			if n > 65535 {
				return nil, errors.New("invalid Base45 value")
			}
			out = append(out, byte(n>>8), byte(n))
		}
		i += group
	}
	return out, nil
}

func encodeZ85(data []byte) (string, error) {
	if len(data)%4 != 0 {
		return "", errors.New("Z85 input length must be a multiple of 4 bytes")
	}
	out := make([]byte, len(data)/4*5)
	for i, o := 0, 0; i < len(data); i, o = i+4, o+5 {
		v := uint64(binary.BigEndian.Uint32(data[i : i+4]))
		for j := 4; j >= 0; j-- {
			out[o+j] = z85Alphabet[v%85]
			v /= 85
		}
	}
	return string(out), nil
}

func decodeZ85(text string) ([]byte, error) {
	if len(text)%5 != 0 {
		return nil, errors.New("Z85 input length must be a multiple of 5 characters")
	}
	out := make([]byte, len(text)/5*4)
	for i, o := 0, 0; i < len(text); i, o = i+5, o+4 {
		var v uint64
		for j := 0; j < 5; j++ {
			idx := strings.IndexByte(z85Alphabet, text[i+j])
			if idx < 0 {
				return nil, errors.New("invalid Z85 character")
			}
			v = v*85 + uint64(idx)
		}
		if v > 1<<32-1 {
			return nil, errors.New("invalid Z85 value")
		}
		binary.BigEndian.PutUint32(out[o:o+4], uint32(v))
	}
	return out, nil
}

func encodeBase91(data []byte) string {
	var out strings.Builder
	var queue uint32
	bits := 0
	for _, c := range data {
		queue |= uint32(c) << bits
		bits += 8
		if bits > 13 {
			v := queue & 8191
			if v > 88 {
				queue >>= 13
				bits -= 13
			} else {
				v = queue & 16383
				queue >>= 14
				bits -= 14
			}
			out.WriteByte(base91Alphabet[v%91])
			out.WriteByte(base91Alphabet[v/91])
		}
	}
	if bits > 0 {
		out.WriteByte(base91Alphabet[queue%91])
		if bits > 7 || queue > 90 {
			out.WriteByte(base91Alphabet[queue/91])
		}
	}
	return out.String()
}

func decodeBase91(text string) ([]byte, error) {
	out := make([]byte, 0, len(text))
	var queue uint32
	bits := 0
	value := -1
	for i := 0; i < len(text); i++ {
		idx := strings.IndexByte(base91Alphabet, text[i])
		if idx < 0 {
			return nil, errors.New("invalid basE91 character")
		}
		if value < 0 {
			value = idx
			continue
		}
		value += idx * 91
		queue |= uint32(value) << bits
		if value&8191 > 88 {
			bits += 13
		} else {
			bits += 14
		}
		for bits >= 8 {
			out = append(out, byte(queue))
			queue >>= 8
			bits -= 8
		}
		value = -1
	}
	if value >= 0 {
		out = append(out, byte(queue|uint32(value)<<bits))
	}
	return out, nil
}

func rot47(text string) string {
	out := []rune(text)
	for i, ch := range out {
		if ch >= '!' && ch <= '~' {
			out[i] = '!' + (ch-'!'+47)%94
		}
	}
	return string(out)
}

func a1z26Encode(text string) string {
	words := strings.Fields(text)
	encoded := make([]string, 0, len(words))
	for _, word := range words {
		letters := make([]string, 0, len(word))
		for _, ch := range strings.ToUpper(word) {
			if ch >= 'A' && ch <= 'Z' {
				letters = append(letters, strconv.Itoa(int(ch-'A'+1)))
			}
		}
		if len(letters) > 0 {
			encoded = append(encoded, strings.Join(letters, "-"))
		}
	}
	return strings.Join(encoded, " / ")
}

func a1z26Decode(text string) (string, error) {
	tokens := strings.Fields(text)
	var out strings.Builder
	needSpace := false
	for _, token := range tokens {
		if token == "/" {
			needSpace = true
			continue
		}
		if needSpace && out.Len() > 0 {
			out.WriteByte(' ')
			needSpace = false
		}
		for _, part := range strings.Split(token, "-") {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > 26 {
				return "", errors.New("invalid A1Z26 format provided")
			}
			out.WriteByte(byte('A' + n - 1))
		}
	}
	return out.String(), nil
}

func jsonEscapeEncode(text string) string {
	quoted := strconv.Quote(text)
	return quoted[1 : len(quoted)-1]
}

func jsonEscapeDecode(text string) (string, error) {
	decoded, err := strconv.Unquote("\"" + text + "\"")
	if err != nil {
		return "", errors.New("invalid JSON string escape provided")
	}
	return decoded, nil
}

func formURLEncode(text string) string { return url.QueryEscape(text) }

func formURLDecode(text string) (string, error) {
	decoded, err := url.QueryUnescape(text)
	if err != nil {
		return "", errors.New("invalid form URL encoding provided")
	}
	return decoded, nil
}

func encodeUTF16Hex(text string, order binary.ByteOrder) string {
	units := utf16.Encode([]rune(text))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		order.PutUint16(raw[i*2:], unit)
	}
	return hex.EncodeToString(raw)
}

func decodeUTF16Hex(text string, order binary.ByteOrder) (string, error) {
	raw, err := decodeCleanHex(text)
	if err != nil || len(raw)%2 != 0 {
		return "", errors.New("invalid UTF-16 hexadecimal data")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = order.Uint16(raw[i*2:])
	}
	if !validUTF16(units) {
		return "", errors.New("invalid UTF-16 surrogate sequence")
	}
	return string(utf16.Decode(units)), nil
}

func validUTF16(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		switch {
		case units[i] >= 0xd800 && units[i] <= 0xdbff:
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return false
			}
			i++
		case units[i] >= 0xdc00 && units[i] <= 0xdfff:
			return false
		}
	}
	return true
}

func encodeUTF32Hex(text string, order binary.ByteOrder) string {
	runes := []rune(text)
	raw := make([]byte, len(runes)*4)
	for i, ch := range runes {
		order.PutUint32(raw[i*4:], uint32(ch))
	}
	return hex.EncodeToString(raw)
}

func decodeUTF32Hex(text string, order binary.ByteOrder) (string, error) {
	raw, err := decodeCleanHex(text)
	if err != nil || len(raw)%4 != 0 {
		return "", errors.New("invalid UTF-32 hexadecimal data")
	}
	runes := make([]rune, 0, len(raw)/4)
	for i := 0; i < len(raw); i += 4 {
		ch := rune(order.Uint32(raw[i:]))
		if !utf8.ValidRune(ch) {
			return "", errors.New("invalid UTF-32 code point")
		}
		runes = append(runes, ch)
	}
	return string(runes), nil
}

func decodeCleanHex(text string) ([]byte, error) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	replacer := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "")
	s = replacer.Replace(s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hexadecimal length")
	}
	return hex.DecodeString(s)
}

func compactASCIIWhitespace(text string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		default:
			return r
		}
	}, text)
}

func decodeBase64Flexible(text string, urlSafe bool) ([]byte, error) {
	s := compactASCIIWhitespace(text)
	if strings.Contains(s, "=") {
		if urlSafe {
			return base64.URLEncoding.DecodeString(s)
		}
		return base64.StdEncoding.DecodeString(s)
	}
	if urlSafe {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func decodeBase32Flexible(text string, hexAlphabet bool) ([]byte, error) {
	s := strings.ToUpper(compactASCIIWhitespace(text))
	enc := base32.StdEncoding
	if hexAlphabet {
		enc = base32.HexEncoding
	}
	if strings.Contains(s, "=") {
		return enc.DecodeString(s)
	}
	return enc.WithPadding(base32.NoPadding).DecodeString(s)
}
