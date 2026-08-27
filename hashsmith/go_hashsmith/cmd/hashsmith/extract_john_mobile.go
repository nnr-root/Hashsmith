package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func runExtractSignal(args []string) error {
	return runFileRecordExtractor("signal2smith", args, extractSignalRecords)
}

func extractSignalRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	start := bytes.Index(b, []byte("<?xml"))
	if start >= 0 {
		b = b[start:]
	}
	values := map[string]string{}
	hasPassword := false
	iterations := 0
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid Signal preferences XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		attrs := map[string]string{}
		for _, attr := range start.Attr {
			attrs[attr.Name.Local] = attr.Value
		}
		switch start.Name.Local {
		case "boolean":
			hasPassword = strings.EqualFold(attrs["value"], "true")
		case "int":
			iterations, _ = strconv.Atoi(attrs["value"])
		case "string":
			var text string
			if err := dec.DecodeElement(&text, &start); err != nil {
				return nil, errors.New("invalid Signal preferences value")
			}
			values[attrs["name"]] = strings.TrimSpace(text)
		}
	}
	if !hasPassword || iterations < 1 || iterations > maxKDFIterations {
		return nil, errors.New("Signal preferences do not contain an enabled password")
	}
	decode := func(name string) ([]byte, error) {
		value := values[name]
		if value == "" {
			return nil, fmt.Errorf("missing Signal %s", name)
		}
		return base64.StdEncoding.DecodeString(value)
	}
	encryptionSalt, e1 := decode("encryption_salt")
	macSalt, e2 := decode("mac_salt")
	secret, e3 := decode("master_secret")
	if e1 != nil || e2 != nil || e3 != nil || len(secret) <= 20 {
		return nil, errors.New("invalid Signal salt or master secret")
	}
	return []string{fmt.Sprintf("$signal$1$%d$%x$%x$%x$%x", iterations,
		encryptionSalt, macSalt, secret, secret[len(secret)-20:])}, nil
}

func runExtractKeychain(args []string) error {
	return runFileRecordExtractor("keychain2smith", args, extractKeychainRecords)
}

func extractKeychainRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	magic := []byte{0xfa, 0xde, 0x07, 0x11}
	at := bytes.LastIndex(b, magic)
	if at < 0 || at+72 > len(b) {
		return nil, errors.New("macOS Keychain database blob not found")
	}
	offset := int(binary.BigEndian.Uint32(b[at+8 : at+12]))
	if offset < 72 || at+offset+48 > len(b) {
		return nil, errors.New("invalid macOS Keychain crypto offset")
	}
	return []string{fmt.Sprintf("$keychain$*%x*%x*%x", b[at+44:at+64], b[at+64:at+72], b[at+offset:at+offset+48])}, nil
}

func runExtractTelegram(args []string) error {
	return runFileRecordExtractor("telegram2smith", args, extractTelegramRecords)
}

func extractTelegramRecords(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return extractTelegramFile(path)
	}
	rootDepth := strings.Count(filepath.Clean(path), string(os.PathSeparator))
	var records []string
	err = filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		depth := strings.Count(filepath.Clean(current), string(os.PathSeparator)) - rootDepth
		if entry.IsDir() {
			if depth > 5 {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasPrefix(name, "map") && !strings.HasPrefix(name, "key_") {
			return nil
		}
		got, parseErr := extractTelegramFile(current)
		if parseErr == nil {
			records = append(records, got...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no Telegram map*/key_* records found")
	}
	return records, nil
}

func extractTelegramFile(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 8 && string(b[:4]) == "TDF$" {
		return extractTelegramTDF(path, b)
	}
	return extractTelegramXML(b)
}

func extractTelegramTDF(path string, b []byte) ([]string, error) {
	if len(b) < 8+16+4+32+4+288 {
		return nil, errors.New("truncated Telegram Desktop TDF file")
	}
	version := binary.LittleEndian.Uint32(b[4:8])
	actual, checksum := b[8:len(b)-16], b[len(b)-16:]
	checkData := append([]byte(nil), actual...)
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(actual)))
	checkData = append(checkData, size[:]...)
	checkData = append(checkData, b[4:8]...)
	checkData = append(checkData, b[:4]...)
	digest := md5.Sum(checkData)
	if !bytes.Equal(checksum, digest[:]) || binary.BigEndian.Uint32(actual[:4]) != 32 {
		return nil, errors.New("invalid Telegram Desktop TDF checksum or salt")
	}
	salt := actual[4:36]
	if binary.BigEndian.Uint32(actual[36:40]) != 288 || len(actual) < 328 {
		return nil, errors.New("invalid Telegram Desktop encrypted key")
	}
	recordVersion, iterations := 1, 4000
	name := strings.ToLower(filepath.Base(path))
	if version >= 2001014 || strings.HasPrefix(name, "key_") {
		recordVersion, iterations = 2, 100000
	}
	return []string{fmt.Sprintf("$telegram$%d*%d*%x*%x", recordVersion, iterations, salt, actual[40:328])}, nil
}

func extractTelegramXML(b []byte) ([]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	values := map[string]string{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid Telegram Android XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "string" {
			continue
		}
		name := ""
		for _, attr := range start.Attr {
			if attr.Name.Local == "name" {
				name = attr.Value
			}
		}
		var text string
		if err := dec.DecodeElement(&text, &start); err != nil {
			return nil, errors.New("invalid Telegram Android XML value")
		}
		values[name] = strings.TrimSpace(text)
	}
	hashText := strings.ToLower(values["passcodeHash1"])
	salt, err := base64.StdEncoding.DecodeString(values["passcodeSalt"])
	if err != nil || len(hashText) != 64 || !allHexValues(hashText) || len(salt) == 0 {
		return nil, errors.New("Telegram Android passcode hash or salt not found")
	}
	return []string{"$telegram$0*" + hashText + "*" + hex.EncodeToString(salt)}, nil
}
