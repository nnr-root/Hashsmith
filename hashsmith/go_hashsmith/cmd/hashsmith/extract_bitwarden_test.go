package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

const bitwardenPublishedRecord = "$bitwarden$0*5000*lulu@mailinator.com*20d9c3c9daaed076026b6cb5887d3273*3bbcb4c7cec45d71c7238291573eb8a8a0f71e6191fb708b07f2cb43b26a56b533ba35a5906abdc08600baedb18fbc042a3b50f4549890210a254129b0ae749394c3c39b33ca183c605ee97b167329d3"

func TestBitwardenPublishedEncryptedKeyVector(t *testing.T) {
	if ok, err := verifyCandidate("openwall123", bitwardenPublishedRecord, "john:bitwarden", "", "prefix"); err != nil || !ok {
		t.Fatalf("published Bitwarden vector: ok=%v err=%v", ok, err)
	}
	if bad, err := verifyCandidate("wrong-password", bitwardenPublishedRecord, "bitwarden", "", "prefix"); err != nil || bad {
		t.Fatalf("wrong Bitwarden password: ok=%v err=%v", bad, err)
	}
}

func TestBitwardenExtractors(t *testing.T) {
	iv, _ := hex.DecodeString("20d9c3c9daaed076026b6cb5887d3273")
	blob, _ := hex.DecodeString("3bbcb4c7cec45d71c7238291573eb8a8a0f71e6191fb708b07f2cb43b26a56b533ba35a5906abdc08600baedb18fbc042a3b50f4549890210a254129b0ae749394c3c39b33ca183c605ee97b167329d3")
	encKey := "0." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(blob)
	jsonData := fmt.Sprintf(`{"userEmail":"LULU@mailinator.com","encKey":"%s"}`, encKey)
	xmlData := fmt.Sprintf(`<map><string name="email">LULU@mailinator.com</string><string name="encKey">%s</string></map>`, encKey)

	levelPath := filepath.Join(t.TempDir(), "nngceckbap-leveldb")
	db, err := leveldb.OpenFile(levelPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Put([]byte("userEmail"), []byte(`"LULU@mailinator.com"`), nil); err == nil {
		err = db.Put([]byte("encKey"), []byte(encKey), nil)
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	paths := map[string]string{
		"json":    extractorFixture(t, "storage.js", []byte(jsonData)),
		"xml":     extractorFixture(t, "preferences.xml", []byte(xmlData)),
		"leveldb": levelPath,
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			records, err := extractBitwardenRecords(path)
			if err != nil || len(records) != 1 || records[0] != bitwardenPublishedRecord {
				t.Fatalf("records=%v err=%v", records, err)
			}
		})
	}
}
