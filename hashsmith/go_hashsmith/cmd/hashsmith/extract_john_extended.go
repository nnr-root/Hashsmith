package main

// Native extractors for additional encrypted artifacts commonly handled by
// John's *2john helpers.  The parsers are independent Go implementations and
// emit the portable record syntax shared by John, Hashcat, and Hashsmith.

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

func runExtractAndroidBackup(args []string) error {
	return runFileRecordExtractor("androidbackup2smith", args, extractAndroidBackupRecords)
}

func extractAndroidBackupRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, err := r.ReadString('\n')
	for err == nil && line != "ANDROID BACKUP\n" { // tolerate vendor preambles
		line, err = r.ReadString('\n')
	}
	if line != "ANDROID BACKUP\n" {
		return nil, errors.New("Android Backup magic not found")
	}
	readLine := func() (string, error) {
		s, e := r.ReadString('\n')
		if e != nil && len(s) == 0 {
			return "", e
		}
		return strings.TrimSpace(s), nil
	}
	versionText, err := readLine()
	if err != nil {
		return nil, errors.New("truncated Android Backup header")
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version < 1 || version > 5 {
		return nil, errors.New("unsupported Android Backup version")
	}
	if _, err = readLine(); err != nil { // compression flag
		return nil, errors.New("truncated Android Backup header")
	}
	algorithm, err := readLine()
	if err != nil || algorithm != "AES-256" {
		return nil, fmt.Errorf("unsupported Android Backup encryption %q", algorithm)
	}
	fields := make([]string, 5)
	for i := range fields {
		fields[i], err = readLine()
		if err != nil {
			return nil, errors.New("truncated Android Backup encryption header")
		}
	}
	userSalt, checkSalt, roundsText, iv, blob := fields[0], fields[1], fields[2], fields[3], fields[4]
	rounds, err := strconv.Atoi(roundsText)
	if err != nil || rounds < 1 || !allHexValues(userSalt, checkSalt, iv, blob) || len(iv) != 32 {
		return nil, errors.New("invalid Android Backup KDF or encryption fields")
	}
	return []string{fmt.Sprintf("$ab$%d*0*%d*%s*%s*%s*%s", version, rounds,
		strings.ToLower(userSalt), strings.ToLower(checkSalt), strings.ToLower(iv), strings.ToLower(blob))}, nil
}

func runExtractEncFS(args []string) error {
	return runFileRecordExtractor("encfs2smith", args, extractEncFSRecords)
}

func extractEncFSRecords(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		path = filepath.Join(path, ".encfs6.xml")
	}
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("invalid EncFS XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		name := start.Name.Local
		switch name {
		case "keySize", "kdfIterations", "saltData", "saltLen", "encodedKeySize", "encodedKeyData":
			var value string
			if e := dec.DecodeElement(&value, &start); e != nil {
				return nil, errors.New("invalid EncFS XML value")
			}
			values[name] = strings.TrimSpace(value)
		case "name":
			if _, exists := values[name]; !exists {
				var value string
				if e := dec.DecodeElement(&value, &start); e == nil {
					values[name] = strings.TrimSpace(value)
				}
			}
		}
	}
	if !strings.Contains(strings.ToUpper(values["name"]), "AES") {
		return nil, errors.New("EncFS volume does not use the supported AES cipher")
	}
	keyBits, e1 := strconv.Atoi(values["keySize"])
	iterations, e2 := strconv.Atoi(values["kdfIterations"])
	saltLen, e3 := strconv.Atoi(values["saltLen"])
	dataLen, e4 := strconv.Atoi(values["encodedKeySize"])
	salt, e5 := decodeBase64Flexible(values["saltData"], false)
	data, e6 := decodeBase64Flexible(values["encodedKeyData"], false)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil ||
		(keyBits != 128 && keyBits != 192 && keyBits != 256) || iterations < 1 ||
		saltLen != len(salt) || dataLen != len(data) || len(data) != keyBits/8+20 {
		return nil, errors.New("invalid EncFS key, KDF, salt, or encoded-key fields")
	}
	return []string{fmt.Sprintf("$encfs$%d*%d*0*%d*%x*%d*%x", keyBits, iterations, saltLen, salt, dataLen, data)}, nil
}

func runExtractMozilla(args []string) error {
	return runFileRecordExtractor("mozilla2smith", args, extractMozillaRecords)
}

func extractMozillaRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	globalAt := bytes.Index(b, []byte("global-salt"))
	checkAt := bytes.Index(b, []byte("password-check"))
	if globalAt < 20 || checkAt < 52 {
		return nil, errors.New("not a supported Mozilla key3.db database")
	}
	globalSalt := b[globalAt-20 : globalAt]
	check := b[checkAt-52 : checkAt]
	entrySalt := check[3:23]
	verifier := check[36:52]
	return []string{fmt.Sprintf("$mozilla$*3*20*1*%x*11*%s*16*%x*20*%x",
		entrySalt, strings.Repeat("00", 11), verifier, globalSalt)}, nil
}

func runExtractMonero(args []string) error {
	return runFileRecordExtractor("monero2smith", args, extractMoneroRecords)
}

func extractMoneroRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, errors.New("empty or truncated Monero keys file")
	}
	return []string{"$monero$0*" + hex.EncodeToString(b)}, nil
}

func runExtractLastPass(args []string) error {
	return runFileRecordExtractor("lastpass2smith", args, extractLastPassRecords)
}

func extractLastPassRecords(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("expected a lastpass-cli data directory containing username, iterations, and verify")
	}
	username, err := os.ReadFile(filepath.Join(path, "username"))
	if err != nil {
		return nil, errors.New("cannot read LastPass username")
	}
	iterationData, err := os.ReadFile(filepath.Join(path, "iterations"))
	if err != nil {
		return nil, errors.New("cannot read LastPass iterations")
	}
	iterations, err := strconv.Atoi(strings.TrimSpace(string(iterationData)))
	if err != nil || iterations < 1 {
		return nil, errors.New("invalid LastPass iteration count")
	}
	verify, err := os.ReadFile(filepath.Join(path, "verify"))
	if err != nil || len(verify) < 64 {
		return nil, errors.New("invalid LastPass verify file")
	}
	account := strings.ToLower(strings.TrimSpace(string(username)))
	if account == "" {
		return nil, errors.New("empty LastPass username")
	}
	return []string{fmt.Sprintf("%x:%d:%s:%x", verify[48:64], iterations, account, verify[32:48])}, nil
}

func runExtractAppleNotes(args []string) error {
	return runFileRecordExtractor("applenotes2smith", args, extractAppleNotesRecords)
}

func extractAppleNotesRecords(path string) ([]string, error) {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT Z_PK, ZCRYPTOITERATIONCOUNT, ZCRYPTOSALT,
		ZCRYPTOWRAPPEDKEY, ZCRYPTOVERIFIER FROM ZICCLOUDSYNCINGOBJECT
		WHERE ZCRYPTOITERATIONCOUNT IS NOT NULL AND ZCRYPTOITERATIONCOUNT > 0`)
	if err != nil {
		return nil, errors.New("not a supported Apple Notes SQLite database")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, iterations int64
		var salt, wrapped, verifier []byte
		if err := rows.Scan(&id, &iterations, &salt, &wrapped, &verifier); err != nil {
			return nil, err
		}
		key := wrapped
		if len(key) == 0 {
			key = verifier
		}
		if id > 0 && iterations > 0 && len(salt) == 16 && len(key) == 24 {
			out = append(out, fmt.Sprintf("$ASN$*%d*%d*%x*%x", id, iterations, salt, key))
		}
	}
	return out, rows.Err()
}

func runExtractBitcoin(args []string) error {
	return runFileRecordExtractor("bitcoin2smith", args, extractBitcoinRecords)
}

func extractBitcoinRecords(path string) ([]string, error) {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err == nil {
		rows, queryErr := db.Query(`SELECT key, value FROM main`)
		if queryErr == nil {
			defer rows.Close()
			var out []string
			for rows.Next() {
				var key, value []byte
				if err := rows.Scan(&key, &value); err != nil {
					db.Close()
					return nil, err
				}
				kind, _, ok := bitcoinCompactBytes(key)
				if !ok || string(kind) != "mkey" {
					continue
				}
				if record, ok := bitcoinMasterKeyRecord(value); ok {
					out = append(out, record)
				}
			}
			db.Close()
			return out, nil
		}
		db.Close()
	}
	return nil, errors.New("unsupported wallet.dat database (SQLite wallets are supported; Berkeley DB requires conversion)")
}

func bitcoinCompactBytes(data []byte) ([]byte, []byte, bool) {
	if len(data) == 0 {
		return nil, data, false
	}
	n, used := uint64(data[0]), 1
	switch data[0] {
	case 253:
		if len(data) < 3 {
			return nil, data, false
		}
		n, used = uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	case 254:
		if len(data) < 5 {
			return nil, data, false
		}
		n, used = uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	case 255:
		if len(data) < 9 {
			return nil, data, false
		}
		n, used = binary.LittleEndian.Uint64(data[1:9]), 9
	}
	if n > uint64(len(data)-used) {
		return nil, data, false
	}
	return data[used : used+int(n)], data[used+int(n):], true
}

func bitcoinMasterKeyRecord(value []byte) (string, bool) {
	encrypted, rest, ok := bitcoinCompactBytes(value)
	if !ok {
		return "", false
	}
	salt, rest, ok := bitcoinCompactBytes(rest)
	if !ok || len(rest) < 8 || len(encrypted) < 32 || len(encrypted)%16 != 0 || len(salt) == 0 {
		return "", false
	}
	method := binary.LittleEndian.Uint32(rest[:4])
	iterations := binary.LittleEndian.Uint32(rest[4:8])
	if method != 0 || iterations == 0 {
		return "", false
	}
	crypted := encrypted[len(encrypted)-32:]
	return fmt.Sprintf("$bitcoin$%d$%x$%d$%x$%d$2$00$2$00", len(crypted)*2, crypted, len(salt)*2, salt, iterations), true
}

var vmxKeySafePattern = regexp.MustCompile(`phrase/([^/]+)/pass2key=([^:]+):cipher=([^:]+):rounds=([0-9]+):salt=([^,]+),([^,]+),([^\\\"\r\n]+)`)

func runExtractVMX(args []string) error {
	return runFileRecordExtractor("vmx2smith", args, extractVMXRecords)
}

func extractVMXRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	m := vmxKeySafePattern.FindSubmatch(b)
	if len(m) != 8 || string(m[2]) != "PBKDF2-HMAC-SHA-1" || string(m[3]) != "AES-256" {
		return nil, errors.New("supported VMware encryption.keySafe record not found")
	}
	rounds, err := strconv.Atoi(string(m[4]))
	salt, saltErr := decodeURLBase64(string(m[5]))
	ciphertext, cipherErr := decodeURLBase64(string(m[6]))
	if err != nil || rounds < 1 || saltErr != nil || cipherErr != nil || len(salt) != 16 || len(ciphertext) < 32 {
		return nil, errors.New("invalid VMware keySafe KDF or cipher data")
	}
	return []string{fmt.Sprintf("$vmx$0$%d$%x$%x", rounds, salt, ciphertext[:32])}, nil
}

func decodeURLBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if n := len(value) % 4; n != 0 {
		value += strings.Repeat("=", 4-n)
	}
	return base64.URLEncoding.DecodeString(value)
}

func runExtractVirtualBox(args []string) error {
	return runFileRecordExtractor("virtualbox2smith", args, extractVirtualBoxRecords)
}

func extractVirtualBoxRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	var encoded string
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("invalid VirtualBox XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "Property" {
			continue
		}
		var name, value string
		for _, attr := range start.Attr {
			switch attr.Name.Local {
			case "name":
				name = attr.Value
			case "value":
				value = attr.Value
			}
		}
		if name == "CRYPT/KeyStore" {
			encoded = value
			break
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 250 || string(raw[:4]) != "VBOX" {
		return nil, errors.New("valid VirtualBox CRYPT/KeyStore property not found")
	}
	keyLength := int(binary.LittleEndian.Uint32(raw[70:74]))
	iter2 := binary.LittleEndian.Uint32(raw[142:146])
	iter1 := binary.LittleEndian.Uint32(raw[178:182])
	encLength := int(binary.LittleEndian.Uint32(raw[182:186]))
	if (keyLength != 32 && keyLength != 64) || encLength < keyLength || encLength > 64 || iter1 == 0 || iter2 == 0 {
		return nil, errors.New("invalid VirtualBox keystore parameters")
	}
	return []string{fmt.Sprintf("$vbox$0$%d$%x$%d$%x$%d$%x$%x", iter1, raw[146:178], keyLength/4,
		raw[186:186+keyLength], iter2, raw[110:142], raw[74:106])}, nil
}

func runExtractDMG(args []string) error {
	return runFileRecordExtractor("dmg2smith", args, extractDMGRecords)
}

func extractDMGRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 1276 && bytes.Equal(b[len(b)-8:], []byte("cdsaencr")) {
		h := b[len(b)-1276:]
		iterations := binary.BigEndian.Uint32(h[48:52])
		saltLen := int(binary.BigEndian.Uint32(h[52:56]))
		aesLen := int(binary.BigEndian.Uint32(h[136:140]))
		hmacLen := int(binary.BigEndian.Uint32(h[436:440]))
		if saltLen < 1 || saltLen > 48 || aesLen < 1 || aesLen > 296 || hmacLen < 1 || hmacLen > 300 || iterations == 0 {
			return nil, errors.New("invalid DMG v1 encryption header")
		}
		return []string{fmt.Sprintf("$dmg$1*%d*%x*%d*%x*%d*%x*%d", saltLen, h[56:56+saltLen],
			aesLen, h[140:140+aesLen], hmacLen, h[440:440+hmacLen], iterations)}, nil
	}
	if len(b) < 264 || !bytes.Equal(b[:8], []byte("encrcdsa")) {
		return nil, errors.New("not a supported encrypted DMG image")
	}
	h := b[:264]
	datasize := binary.BigEndian.Uint64(h[56:64])
	dataoffset := binary.BigEndian.Uint64(h[64:72])
	iterations := binary.BigEndian.Uint32(h[104:108])
	saltLen := int(binary.BigEndian.Uint32(h[108:112]))
	blobSize := int(binary.BigEndian.Uint32(h[196:200]))
	if saltLen < 1 || saltLen > 32 || blobSize < 1 || blobSize > 64 || iterations == 0 || datasize < 4096 || dataoffset > uint64(len(b)) {
		return nil, errors.New("invalid DMG v2 encryption header")
	}
	cno := (datasize+4095)/4096 - 2
	dataSize := datasize - cno*4096
	start := dataoffset + cno*4096
	if dataSize > uint64(len(b)) || start > uint64(len(b))-dataSize || dataoffset > uint64(len(b))-4096 {
		return nil, errors.New("truncated DMG v2 encrypted data")
	}
	return []string{fmt.Sprintf("$dmg$2*%d*%x*32*%x*%d*%x*%d*%d*%x*1*%x*%d", saltLen, h[112:112+saltLen],
		h[148:180], blobSize, h[200:200+blobSize], cno, dataSize, b[start:start+dataSize], b[dataoffset:dataoffset+4096], iterations)}, nil
}

func runExtractBitLocker(args []string) error {
	fs := flag.NewFlagSet("bitlocker2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "BitLocker image path")
	offset := fs.Int64("offset", 0, "partition byte offset")
	outFile := fs.String("o", "", "write records to file")
	copyRes := fs.Bool("c", false, "copy records to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	paths := fs.Args()
	if *filePath != "" {
		paths = append([]string{*filePath}, paths...)
	}
	if len(paths) == 0 {
		return errors.New("bitlocker2smith requires -f <image>")
	}
	var records []string
	for _, path := range paths {
		got, err := extractBitLockerRecords(path, *offset)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		records = append(records, got...)
	}
	records = uniqueNonEmpty(records)
	if len(records) == 0 {
		return errors.New("no password- or recovery-password-protected BitLocker VMK found")
	}
	clrGreen.Fprintf(os.Stderr, "Extracted %d crack-ready BitLocker record(s)\n", len(records))
	return outputResult(strings.Join(records, "\n"), *outFile, *copyRes)
}

func extractBitLockerRecords(path string, partitionOffset int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	readAt := func(offset int64, n int) ([]byte, error) {
		b := make([]byte, n)
		_, e := f.ReadAt(b, offset)
		return b, e
	}
	header, err := readAt(partitionOffset, 0x1c0)
	if err != nil {
		return nil, errors.New("truncated BitLocker volume header")
	}
	if len(header) < 11 {
		return nil, errors.New("truncated BitLocker volume header")
	}
	signature := string(header[3:11])
	guidOffset := 0
	switch signature {
	case "-FVE-FS-":
		guidOffset = 0xa0
	case "MSWIN4.1":
		guidOffset = 0x1a8
	default:
		return nil, errors.New("BitLocker volume signature not found")
	}
	if guidOffset+40 > len(header) {
		return nil, errors.New("truncated BitLocker metadata pointers")
	}
	var metadataOffset uint64
	for i := 0; i < 3; i++ {
		v := binary.LittleEndian.Uint64(header[guidOffset+16+i*8 : guidOffset+24+i*8])
		if v != 0 {
			metadataOffset = v
			break
		}
	}
	if metadataOffset == 0 {
		return nil, errors.New("BitLocker metadata pointer is empty")
	}
	prefix, err := readAt(partitionOffset+int64(metadataOffset), 112)
	if err != nil {
		return nil, errors.New("cannot read BitLocker metadata header")
	}
	size := int(binary.LittleEndian.Uint32(prefix[64:68]))
	if size < 120 || size > 64<<20 {
		return nil, errors.New("invalid BitLocker metadata size")
	}
	metadata, err := readAt(partitionOffset+int64(metadataOffset), size)
	if err != nil {
		return nil, errors.New("truncated BitLocker metadata block")
	}
	return parseBitLockerMetadata(metadata), nil
}

func parseBitLockerMetadata(metadata []byte) []string {
	var out []string
	for pos := 112; pos+8 <= len(metadata); {
		entry, next, ok := bitLockerEntry(metadata, pos)
		if !ok {
			break
		}
		if entry.valueType == 8 {
			out = append(out, bitLockerVMKRecords(entry.data)...)
		}
		pos = next
	}
	return uniqueNonEmpty(out)
}

type bitLockerMetadataEntry struct {
	valueType uint16
	data      []byte
}

func bitLockerEntry(block []byte, pos int) (bitLockerMetadataEntry, int, bool) {
	if pos < 0 || pos+8 > len(block) {
		return bitLockerMetadataEntry{}, pos, false
	}
	size := int(binary.LittleEndian.Uint16(block[pos : pos+2]))
	if size < 8 || pos+size > len(block) {
		return bitLockerMetadataEntry{}, pos, false
	}
	return bitLockerMetadataEntry{binary.LittleEndian.Uint16(block[pos+4 : pos+6]), block[pos+8 : pos+size]}, pos + size, true
}

func bitLockerVMKRecords(vmk []byte) []string {
	if len(vmk) < 28 {
		return nil
	}
	protection := binary.LittleEndian.Uint16(vmk[26:28])
	if protection != 0x2000 && protection != 0x800 {
		return nil
	}
	var salt []byte
	var out []string
	for pos := 28; pos+8 <= len(vmk); {
		entry, next, ok := bitLockerEntry(vmk, pos)
		if !ok {
			break
		}
		switch entry.valueType {
		case 3:
			if len(entry.data) >= 20 {
				salt = append([]byte(nil), entry.data[4:20]...)
			}
		case 5:
			if len(salt) == 16 && len(entry.data) > 28 {
				versions := []int{0, 1}
				if protection == 0x800 {
					versions = []int{2, 3}
				}
				for _, version := range versions {
					out = append(out, fmt.Sprintf("$bitlocker$%d$16$%x$1048576$12$%x$%d$%x", version, salt,
						entry.data[:12], len(entry.data)-12, entry.data[12:]))
				}
			}
		}
		pos = next
	}
	return out
}
