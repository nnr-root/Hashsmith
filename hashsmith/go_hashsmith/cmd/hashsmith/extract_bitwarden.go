package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func runExtractBitwarden(args []string) error {
	return runFileRecordExtractor("bitwarden2smith", args, extractBitwardenRecords)
}

func extractBitwardenRecords(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var email, encryptedKey string
	if info.IsDir() {
		db, openErr := leveldb.OpenFile(path, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
		if openErr != nil {
			return nil, fmt.Errorf("open Bitwarden browser LevelDB: %w", openErr)
		}
		defer db.Close()
		emailBytes, e1 := db.Get([]byte("userEmail"), nil)
		keyBytes, e2 := db.Get([]byte("encKey"), nil)
		if e1 != nil || e2 != nil {
			return nil, errors.New("Bitwarden userEmail or encKey not found in LevelDB")
		}
		email = strings.Trim(string(emailBytes), "\" \t\r\n")
		encryptedKey = strings.Trim(string(keyBytes), "\" \t\r\n")
	} else {
		b, readErr := readExtractorFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if bytes.HasPrefix(bytes.TrimSpace(b), []byte("<")) {
			email, encryptedKey, err = parseBitwardenXML(b)
		} else {
			var values map[string]json.RawMessage
			if err = json.Unmarshal(b, &values); err == nil {
				err = json.Unmarshal(values["userEmail"], &email)
				if err == nil {
					err = json.Unmarshal(values["encKey"], &encryptedKey)
				}
			}
		}
		if err != nil {
			return nil, errors.New("invalid Bitwarden JSON/XML storage")
		}
	}
	return bitwardenEncryptedKeyRecord(email, encryptedKey)
}

func parseBitwardenXML(b []byte) (string, string, error) {
	values := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
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
		var value string
		if err := dec.DecodeElement(&value, &start); err != nil {
			return "", "", err
		}
		values[name] = strings.TrimSpace(value)
	}
	return values["email"], values["encKey"], nil
}

func bitwardenEncryptedKeyRecord(email, encryptedKey string) ([]string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parts := strings.Split(encryptedKey, "|")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "0.") || email == "" {
		return nil, errors.New("invalid Bitwarden email or encrypted key")
	}
	iv, e1 := base64.StdEncoding.DecodeString(strings.TrimPrefix(parts[0], "0."))
	blob, e2 := base64.StdEncoding.DecodeString(parts[1])
	if e1 != nil || e2 != nil || len(iv) != 16 || len(blob) < 32 || len(blob)%16 != 0 {
		return nil, errors.New("invalid Bitwarden encrypted-key payload")
	}
	return []string{fmt.Sprintf("$bitwarden$0*5000*%s*%s*%s", email, hex.EncodeToString(iv), hex.EncodeToString(blob))}, nil
}
