package main

// Native-Go importers for common files handled by John's *2john ecosystem.
// These implementations intentionally emit Hashsmith's already-supported,
// canonical records; they do not execute scripts or require Python/Perl.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type extractorFileParser func(string) ([]string, error)

func runExtractOnePassword(args []string) error {
	return runFileRecordExtractor("1password2smith", args, extractOnePasswordRecords)
}

func extractOnePasswordRecords(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		path = filepath.Join(path, "data", "default", "encryptionKeys.js")
	}
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var root struct {
		List []struct {
			Data       string `json:"data"`
			Iterations int    `json:"iterations"`
		} `json:"list"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, errors.New("invalid 1Password encryptionKeys.js JSON")
	}
	var out []string
	for _, key := range root.List {
		encoded := strings.TrimSpace(key.Data)
		raw, err := decodeBase64Flexible(encoded, false)
		if err != nil && len(encoded) > 1 {
			// Old Agile Keychain exports sometimes append a non-base64 marker.
			raw, err = decodeBase64Flexible(encoded[:len(encoded)-1], false)
		}
		if err != nil || len(raw) < 48 {
			continue
		}
		iterations := key.Iterations
		if iterations == 0 {
			iterations = 1000
		}
		var salt, data []byte
		if bytes.HasPrefix(raw, []byte("Salted__")) && len(raw) >= 48 {
			salt, data = raw[8:16], raw[16:]
		} else {
			salt, data = make([]byte, 8), raw
		}
		if len(data) < 32 || len(data)%16 != 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%d:%x:%x", iterations, salt, data))
	}
	return out, nil
}

func runExtractITunes(args []string) error {
	return runFileRecordExtractor("itunes2smith", args, extractITunesRecords)
}

func extractITunesRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	salt, okSalt := findITunesKeybagValue(b, "SALT")
	iterRaw, okIter := findITunesKeybagValue(b, "ITER")
	wpky, okWPKY := findITunesKeybagValue(b, "WPKY")
	if !okSalt || !okIter || !okWPKY || len(salt) != 20 || len(iterRaw) != 4 || len(wpky) != 40 {
		return nil, errors.New("Manifest.plist lacks a valid SALT/ITER/WPKY backup keybag")
	}
	iterations := binary.BigEndian.Uint32(iterRaw)
	if iterations == 0 {
		return nil, errors.New("invalid zero iTunes backup iteration count")
	}
	dpicRaw, okDPIC := findITunesKeybagValue(b, "DPIC")
	dpsl, okDPSL := findITunesKeybagValue(b, "DPSL")
	if okDPIC || okDPSL {
		if !okDPIC || !okDPSL || len(dpicRaw) != 4 || len(dpsl) != 20 || binary.BigEndian.Uint32(dpicRaw) == 0 {
			return nil, errors.New("incomplete or invalid iOS 10 DPIC/DPSL keybag fields")
		}
		return []string{fmt.Sprintf("$itunes_backup$*10*%x*%d*%x*%x*%d", wpky, iterations, salt, dpsl, binary.BigEndian.Uint32(dpicRaw))}, nil
	}
	return []string{fmt.Sprintf("$itunes_backup$*9*%x*%d*%x**", wpky, iterations, salt)}, nil
}

func findITunesKeybagValue(data []byte, tag string) ([]byte, bool) {
	needle := []byte(tag)
	for start := 0; start+8 <= len(data); {
		i := bytes.Index(data[start:], needle)
		if i < 0 {
			break
		}
		i += start
		if i+8 <= len(data) {
			n := int(binary.BigEndian.Uint32(data[i+4 : i+8]))
			if n >= 0 && n <= 1<<20 && i+8+n <= len(data) {
				return append([]byte(nil), data[i+8:i+8+n]...), true
			}
		}
		start = i + 1
	}
	return nil, false
}

func runFileRecordExtractor(command string, args []string, parse extractorFileParser) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "input file path")
	outFile := fs.String("o", "", "write records to file")
	copyRes := fs.Bool("c", false, "copy records to clipboard")
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			fmt.Fprintf(os.Stderr, "Usage: hashsmith %s -f <file> [-o out] [-c]\n", command)
			return nil
		}
	}
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	paths := append([]string(nil), fs.Args()...)
	if *filePath != "" {
		paths = append([]string{*filePath}, paths...)
	}
	if len(paths) == 0 {
		return fmt.Errorf("%s requires -f <file> (or one or more path arguments)", command)
	}
	var records []string
	for _, path := range paths {
		got, err := parse(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		records = append(records, got...)
	}
	records = uniqueNonEmpty(records)
	if len(records) == 0 {
		return fmt.Errorf("%s found no supported password records", command)
	}
	clrGreen.Fprintf(os.Stderr, "Extracted %d crack-ready record(s) from %d file(s)\n", len(records), len(paths))
	return outputResult(strings.Join(records, "\n"), *outFile, *copyRes)
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func readExtractorFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read input: %w", err)
	}
	return b, nil
}

func runExtractAnsible(args []string) error {
	return runFileRecordExtractor("ansible2smith", args, extractAnsibleRecords)
}

func extractAnsibleRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	if len(lines) < 2 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "$ANSIBLE_VAULT;") ||
		!strings.HasSuffix(strings.TrimSpace(lines[0]), ";AES256") {
		return nil, errors.New("not an AES-256 Ansible Vault file")
	}
	outer, err := hex.DecodeString(strings.Join(strings.Fields(strings.Join(lines[1:], "")), ""))
	if err != nil {
		return nil, errors.New("invalid Ansible Vault hexadecimal payload")
	}
	parts := bytes.SplitN(outer, []byte{'\n'}, 3)
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return nil, errors.New("invalid Ansible Vault salt/HMAC/ciphertext envelope")
	}
	return []string{fmt.Sprintf("$ansible$0*0*%s*%s*%s", parts[0], parts[1], parts[2])}, nil
}

func runExtractEthereum(args []string) error {
	return runFileRecordExtractor("ethereum2smith", args, extractEthereumRecords)
}

func extractEthereumRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, errors.New("invalid Ethereum keystore JSON")
	}
	cryptoObj, ok := mapValueCI(root, "crypto")
	if !ok {
		return nil, errors.New("Ethereum keystore has no crypto object")
	}
	cryptoMap, ok := cryptoObj.(map[string]any)
	if !ok {
		return nil, errors.New("invalid Ethereum crypto object")
	}
	cipherName, _ := stringValueCI(cryptoMap, "cipher")
	if !strings.EqualFold(cipherName, "aes-128-ctr") {
		return nil, fmt.Errorf("unsupported Ethereum cipher %q", cipherName)
	}
	kdf, _ := stringValueCI(cryptoMap, "kdf")
	ciphertext, _ := stringValueCI(cryptoMap, "ciphertext")
	mac, _ := stringValueCI(cryptoMap, "mac")
	paramsObj, ok := mapValueCI(cryptoMap, "kdfparams")
	if !ok {
		return nil, errors.New("Ethereum keystore has no kdfparams")
	}
	params, ok := paramsObj.(map[string]any)
	if !ok {
		return nil, errors.New("invalid Ethereum kdfparams")
	}
	salt, _ := stringValueCI(params, "salt")
	if !allHexValues(salt, ciphertext, mac) {
		return nil, errors.New("Ethereum salt, ciphertext or MAC is not hexadecimal")
	}
	switch strings.ToLower(kdf) {
	case "scrypt":
		n, okN := intValueCI(params, "n")
		r, okR := intValueCI(params, "r")
		p, okP := intValueCI(params, "p")
		if !okN || !okR || !okP || n < 2 || r < 1 || p < 1 {
			return nil, errors.New("invalid Ethereum scrypt parameters")
		}
		return []string{fmt.Sprintf("$ethereum$s*%d*%d*%d*%s*%s*%s", n, r, p, strings.ToLower(salt), strings.ToLower(ciphertext), strings.ToLower(mac))}, nil
	case "pbkdf2":
		c, ok := intValueCI(params, "c")
		prf, _ := stringValueCI(params, "prf")
		if !ok || c < 1 || !strings.EqualFold(prf, "hmac-sha256") {
			return nil, errors.New("Ethereum PBKDF2 must use hmac-sha256 with a positive iteration count")
		}
		return []string{fmt.Sprintf("$ethereum$p*%d*%s*%s*%s", c, strings.ToLower(salt), strings.ToLower(ciphertext), strings.ToLower(mac))}, nil
	default:
		return nil, fmt.Errorf("unsupported Ethereum KDF %q", kdf)
	}
}

func mapValueCI(m map[string]any, key string) (any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func stringValueCI(m map[string]any, key string) (string, bool) {
	v, ok := mapValueCI(m, key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func intValueCI(m map[string]any, key string) (int, bool) {
	v, ok := mapValueCI(m, key)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		x, err := strconv.Atoi(n.String())
		return x, err == nil
	case float64:
		return int(n), n == float64(int(n))
	case string:
		x, err := strconv.Atoi(n)
		return x, err == nil
	}
	return 0, false
}

func allHexValues(values ...string) bool {
	for _, value := range values {
		if value == "" || len(value)%2 != 0 || !isHex(value) {
			return false
		}
	}
	return true
}

func runExtractBlockchain(args []string) error {
	return runFileRecordExtractor("blockchain2smith", args, extractBlockchainRecords)
}

func extractBlockchainRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, errors.New("invalid Blockchain wallet JSON")
	}
	payload, ok := stringValueCI(root, "payload")
	if !ok {
		return nil, errors.New("wallet has no payload")
	}
	iterations, ok := intValueCI(root, "pbkdf2_iterations")
	if !ok || iterations < 1 {
		return nil, errors.New("wallet has no valid pbkdf2_iterations")
	}
	raw, err := decodeBase64Flexible(payload, false)
	if err != nil || len(raw) < 16 {
		return nil, errors.New("wallet payload is not valid base64 ciphertext")
	}
	return []string{fmt.Sprintf("$blockchain$v2$%d$%d$%x", iterations, len(raw), raw)}, nil
}

func runExtractElectrum(args []string) error {
	return runFileRecordExtractor("electrum2smith", args, extractElectrumRecords)
}

func extractElectrumRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var candidates []string
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "{") {
		var root any
		if json.Unmarshal(b, &root) == nil {
			collectElectrumStrings(root, false, &candidates)
		}
	} else {
		candidates = append(candidates, trimmed)
	}
	for _, encoded := range candidates {
		raw, err := decodeBase64Flexible(encoded, false)
		if err != nil {
			continue
		}
		var kind int
		var iv, ciphertext []byte
		switch len(raw) {
		case 64:
			kind, iv, ciphertext = 1, raw[:16], raw[16:32]
		case 128:
			kind, iv, ciphertext = 2, raw[:16], raw[16:32]
		case 80:
			kind, iv, ciphertext = 3, raw[len(raw)-32:len(raw)-16], raw[len(raw)-16:]
		default:
			continue
		}
		return []string{fmt.Sprintf("$electrum$%d*%x*%x", kind, iv, ciphertext)}, nil
	}
	return nil, errors.New("no supported legacy Electrum encrypted seed/xprv/private-key field found")
}

// collectElectrumStrings visits wallet key material first and walks maps in a
// stable order. A generic JSON string walk is deliberately avoided here: a
// base64 note or transaction blob can coincidentally have a wallet-key length.
func collectElectrumStrings(v any, keyMaterial bool, out *[]string) {
	switch x := v.(type) {
	case string:
		if keyMaterial {
			*out = append(*out, x)
		}
	case []any:
		for _, item := range x {
			collectElectrumStrings(item, keyMaterial, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lower := strings.ToLower(key)
			target := keyMaterial || lower == "seed" || lower == "xprv" || lower == "keypairs" ||
				lower == "master_private_keys" || lower == "imported"
			collectElectrumStrings(x[key], target, out)
		}
	}
}

func runExtractMultiBit(args []string) error {
	return runFileRecordExtractor("multibit2smith", args, extractMultiBitRecords)
}

func extractMultiBitRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	encoded := strings.Join(strings.Fields(string(b)), "")
	if len(encoded) > 64 {
		encoded = encoded[:64]
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 48 || string(raw[:8]) != "Salted__" {
		return nil, errors.New("not a supported MultiBit Classic OpenSSL-salted key")
	}
	return []string{fmt.Sprintf("$multibit$1*%x*%x", raw[8:16], raw[16:48])}, nil
}

func runExtractProsody(args []string) error {
	return runFileRecordExtractor("prosody2smith", args, extractProsodyRecords)
}

var prosodyAssignment = regexp.MustCompile(`(?m)^\s*([A-Za-z_]+)\s*=\s*["']?([^"';\r\n]+)`)

func extractProsodyRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, match := range prosodyAssignment.FindAllStringSubmatch(string(b), -1) {
		values[strings.ToLower(match[1])] = strings.TrimSpace(match[2])
	}
	iterations, err := strconv.Atoi(values["iteration_count"])
	salt, stored := values["salt"], values["stored_key"]
	if err != nil || iterations < 1 || salt == "" || len(stored) != 40 || !isHex(stored) {
		return nil, errors.New("Prosody file lacks valid iteration_count, salt or stored_key values")
	}
	return []string{fmt.Sprintf("$xmpp-scram$0$%d$%d$%x$%s", iterations, len(salt), []byte(salt), strings.ToLower(stored))}, nil
}

func runExtractAIX(args []string) error {
	return runFileRecordExtractor("aix2smith", args, extractAIXRecords)
}

func extractAIXRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "password") {
			if _, value, ok := strings.Cut(line, "="); ok {
				hash := strings.TrimSpace(value)
				if isAIX(hash) {
					out = append(out, hash)
				}
			}
		} else if isAIX(line) {
			out = append(out, line)
		}
	}
	return out, nil
}

func runExtractAruba(args []string) error {
	return runFileRecordExtractor("aruba2smith", args, extractArubaRecords)
}

func extractArubaRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.LastIndexByte(line, ':'); i >= 0 {
			line = strings.TrimSpace(line[i+1:])
		}
		if len(line) == 50 && isHex(line) && strings.EqualFold(line[8:10], "01") {
			out = append(out, strings.ToLower(line))
		}
	}
	return out, nil
}

func runExtractLDIF(args []string) error {
	return runFileRecordExtractor("ldif2smith", args, extractLDIFRecords)
}

func extractLDIFRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	// RFC 2849 continuation lines begin with one space.
	text := strings.ReplaceAll(string(b), "\r", "")
	text = strings.ReplaceAll(text, "\n ", "")
	var out []string
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		var value string
		switch {
		case strings.HasPrefix(lower, "userpassword::"):
			encoded := strings.TrimSpace(line[len("userPassword::"):])
			raw, err := decodeBase64Flexible(encoded, false)
			if err != nil {
				continue
			}
			value = string(raw)
		case strings.HasPrefix(lower, "userpassword:"):
			value = strings.TrimSpace(line[len("userPassword:"):])
		}
		if isLDAP(value) || looksLikeCryptHash(value) {
			out = append(out, value)
		}
	}
	return out, nil
}

func runExtractHtpasswd(args []string) error {
	return runFileRecordExtractor("htpasswd2smith", args, extractHtpasswdRecords)
}

func extractHtpasswdRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, hash, ok := strings.Cut(line, ":")
		if !ok {
			hash = line
		}
		hash = strings.TrimSpace(hash)
		if looksLikeCryptHash(hash) || isLDAP(hash) {
			out = append(out, hash)
		}
	}
	return out, nil
}

func runExtractHashdump(args []string) error {
	return runFileRecordExtractor("hashdump2smith", args, extractHashdumpRecords)
}

const (
	emptyLM   = "aad3b435b51404eeaad3b435b51404ee"
	emptyNTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

func extractHashdumpRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// pwdump/secretsdump: user:RID:LM:NTLM[:...]
		if len(fields) >= 4 && len(fields[2]) == 32 && isHex(fields[2]) && len(fields[3]) == 32 && isHex(fields[3]) {
			if !strings.EqualFold(fields[3], emptyNTLM) {
				out = append(out, strings.ToLower(fields[3]))
			}
			if !strings.EqualFold(fields[2], emptyLM) {
				out = append(out, strings.ToLower(fields[2]))
			}
			continue
		}
		// Also accept a simple user:32hex export.
		if len(fields) == 2 && len(fields[1]) == 32 && isHex(fields[1]) {
			out = append(out, strings.ToLower(fields[1]))
		}
	}
	return out, nil
}

func runExtractHCCAPX(args []string) error {
	return runFileRecordExtractor("hccapx2smith", args, extractHCCAPXRecords)
}

func extractHCCAPXRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b)%hccapxSize != 0 {
		return nil, fmt.Errorf("invalid hccapx length %d (must be a multiple of %d)", len(b), hccapxSize)
	}
	var out []string
	for offset := 0; offset < len(b); offset += hccapxSize {
		record := hex.EncodeToString(b[offset : offset+hccapxSize])
		if _, err := parseHCCAPX(record); err != nil {
			return nil, fmt.Errorf("invalid hccapx record %d: %w", offset/hccapxSize+1, err)
		}
		out = append(out, record)
	}
	return out, nil
}

func runExtractTrueCrypt(args []string) error {
	return runFileRecordExtractor("truecrypt2smith", args, func(path string) ([]string, error) {
		return extractCryptHeaderRecords(path, "truecrypt")
	})
}

func runExtractVeraCrypt(args []string) error {
	return runFileRecordExtractor("veracrypt2smith", args, func(path string) ([]string, error) {
		return extractCryptHeaderRecords(path, "veracrypt")
	})
}

func extractCryptHeaderRecords(path, kind string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 512 {
		return nil, fmt.Errorf("volume is only %d bytes; need the first 512-byte encrypted header", len(b))
	}
	return []string{kind + ":" + hex.EncodeToString(b[:512])}, nil
}

func runExtractIKE(args []string) error {
	return runFileRecordExtractor("ike2smith", args, extractIKERecords)
}

func extractIKERecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "$ike$*0*") {
			line = strings.TrimPrefix(line, "$ike$*0*")
			line = strings.ReplaceAll(line, "*", ":")
		}
		if isIKE(line) {
			out = append(out, strings.ToLower(line))
		}
	}
	return out, nil
}

func runExtractSIP(args []string) error {
	return runFileRecordExtractor("sip2smith", args, extractSIPRecords)
}

func extractSIPRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "$sip$*"); i >= 0 {
			out = append(out, line[i:])
			continue
		}
		line = strings.ReplaceAll(line, `sip:*`, `sip:0.0.0.0`)
		line = strings.NewReplacer(`"`, "*", ":", "*").Replace(line)
		fields := strings.Split(line, "*")
		if len(fields) == 13 {
			fields = append(fields[:7], append([]string{""}, fields[7:]...)...)
		}
		if len(fields) >= 14 {
			out = append(out, "$sip$*"+strings.Join(fields, "*"))
		}
	}
	return out, nil
}

func runExtractScan(args []string) error {
	return runFileRecordExtractor("scan2smith", args, extractScannedRecords)
}

func extractScannedRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(detectHashTypes(line)) > 0 {
			out = append(out, line)
			continue
		}
		for _, token := range strings.FieldsFunc(line, func(r rune) bool {
			switch r {
			case ' ', '\t', '=', ',', ';', '[', ']', '(', ')', '<', '>', '"', '\'':
				return true
			}
			return false
		}) {
			if len(detectHashTypes(token)) > 0 {
				out = append(out, token)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
