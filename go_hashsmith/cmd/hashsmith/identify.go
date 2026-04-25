package main

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

func runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text     := fs.String("i", "", "text")
	filePath := fs.String("f", "", "file path")
	outFile  := fs.String("o", "", "output file")
	copyRes  := fs.Bool("c", false, "copy to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	value, err := readInput(*text, *filePath)
	if err != nil || strings.TrimSpace(value) == "" {
		return errors.New("identify requires -i text or -f file")
	}
	result := identifyText(strings.TrimSpace(value))
	if *outFile == "" && !*copyRes {
		// styled direct output — skips plain stdout duplicate
		color.New(themeAttr).Fprintln(os.Stdout, result)
		return nil
	}
	return outputResult(result, *outFile, *copyRes)
}

func identifyText(value string) string {
	encodings := detectEncodingTypes(value)
	hashes    := detectHashTypes(value)

	var lines []string
	if len(encodings) > 0 && !(len(encodings) == 1 && encodings[0] == "hex" && len(hashes) > 0) {
		for _, e := range encodings {
			lines = append(lines, e+" encoded text")
		}
		return strings.Join(lines, "\n")
	}
	if len(hashes) > 0 {
		for _, h := range hashes {
			lines = append(lines, "100% "+h)
		}
		return strings.Join(lines, "\n")
	}
	return "Probably raw text"
}

func detectEncodingTypes(text string) []string {
	out := make([]string, 0, 4)
	if isHex(text) && len(text)%2 == 0 {
		out = append(out, "hex")
	}
	if looksBase64(text) {
		out = append(out, "base64")
	}
	if looksBase64URL(text) {
		out = append(out, "base64url")
	}
	if looksBase32(text) {
		out = append(out, "base32")
	}
	if looksBinary(text) {
		out = append(out, "binary")
	}
	if looksDecimal(text) {
		out = append(out, "decimal")
	}
	if looksOctal(text) {
		out = append(out, "octal")
	}
	if looksMorse(text) {
		out = append(out, "morse")
	}
	return unique(out)
}

func detectHashTypes(text string) []string {
	t := strings.TrimSpace(text)
	l := strings.ToLower(t)

	if strings.HasPrefix(l, "$2a$") || strings.HasPrefix(l, "$2b$") || strings.HasPrefix(l, "$2y$") {
		return []string{"bcrypt"}
	}
	if strings.HasPrefix(l, "$argon2") {
		return []string{"argon2"}
	}
	if strings.HasPrefix(l, "scrypt$") {
		return []string{"scrypt"}
	}
	if strings.HasPrefix(l, "md5") && len(t) == 35 && isHex(t[3:]) {
		return []string{"postgres"}
	}
	if strings.HasPrefix(l, "0x0100") {
		return []string{"mssql2005", "mssql2012"}
	}
	if !isHex(t) {
		return nil
	}

	switch len(t) {
	case 16:
		return []string{"mysql323"}
	case 32:
		return []string{"md5", "md4", "ntlm"}
	case 40:
		return []string{"sha1", "ripemd160"}
	case 56:
		return []string{"sha224"}
	case 64:
		return []string{"sha256", "sha3_256", "blake2s"}
	case 96:
		return []string{"sha384"}
	case 128:
		return []string{"sha512", "sha3_512", "blake2b"}
	default:
		return nil
	}
}

func looksBase64(s string) bool {
	if !regexp.MustCompile(`^[A-Za-z0-9+/=]+$`).MatchString(s) {
		return false
	}
	if len(s)%4 != 0 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func looksBase64URL(s string) bool {
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(s) {
		return false
	}
	padding := strings.Repeat("=", (4-len(s)%4)%4)
	_, err := base64.URLEncoding.DecodeString(s + padding)
	return err == nil
}

func looksBase32(s string) bool {
	if !regexp.MustCompile(`^[A-Z2-7=]+$`).MatchString(strings.ToUpper(s)) {
		return false
	}
	_, err := base32.StdEncoding.DecodeString(strings.ToUpper(s))
	return err == nil
}

func looksBinary(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if len(p) != 8 {
			return false
		}
		for _, ch := range p {
			if ch != '0' && ch != '1' {
				return false
			}
		}
	}
	return true
}

func looksDecimal(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

func looksOctal(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if !regexp.MustCompile(`^[0-7]+$`).MatchString(p) {
			return false
		}
		v, err := strconv.ParseInt(p, 8, 32)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

func looksMorse(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch != '.' && ch != '-' && ch != '/' && ch != ' ' {
			return false
		}
	}
	return strings.ContainsRune(s, '.') || strings.ContainsRune(s, '-')
}

func unique(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
