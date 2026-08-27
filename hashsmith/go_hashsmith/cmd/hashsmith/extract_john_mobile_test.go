package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignalExtractorPublishedRecord(t *testing.T) {
	f := strings.Split(strings.TrimPrefix(signalPublishedRecord, "$signal$"), "$")
	encSalt, _ := hex.DecodeString(f[2])
	macSalt, _ := hex.DecodeString(f[3])
	secret, _ := hex.DecodeString(f[4])
	xml := `<map><boolean name="have_password" value="true"/><int name="passphrase_iterations" value="` + f[1] + `"/>` +
		`<string name="encryption_salt">` + base64.StdEncoding.EncodeToString(encSalt) + `</string>` +
		`<string name="mac_salt">` + base64.StdEncoding.EncodeToString(macSalt) + `</string>` +
		`<string name="master_secret">` + base64.StdEncoding.EncodeToString(secret) + `</string></map>`
	got, err := extractSignalRecords(extractorFixture(t, "SecureSMS-Preferences.xml", []byte(xml)))
	if err != nil || len(got) != 1 || got[0] != signalPublishedRecord {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestKeychainExtractorPublishedRecord(t *testing.T) {
	f := strings.Split(strings.TrimPrefix(keychainPublishedRecord, "$keychain$*"), "*")
	salt, _ := hex.DecodeString(f[0])
	iv, _ := hex.DecodeString(f[1])
	ct, _ := hex.DecodeString(f[2])
	blob := make([]byte, 160)
	copy(blob, []byte{0xfa, 0xde, 0x07, 0x11})
	binary.BigEndian.PutUint32(blob[8:12], 96)
	copy(blob[44:64], salt)
	copy(blob[64:72], iv)
	copy(blob[96:144], ct)
	got, err := extractKeychainRecords(extractorFixture(t, "login.keychain", blob))
	if err != nil || len(got) != 1 || got[0] != keychainPublishedRecord {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTelegramExtractors(t *testing.T) {
	t.Run("android-xml", func(t *testing.T) {
		salt := []byte("telegram-salt")
		hash := strings.Repeat("ab", 32)
		xml := `<map><string name="passcodeHash1">` + hash + `</string><string name="passcodeSalt">` +
			base64.StdEncoding.EncodeToString(salt) + `</string></map>`
		got, err := extractTelegramRecords(extractorFixture(t, "userconfig.xml", []byte(xml)))
		want := "$telegram$0*" + hash + "*" + hex.EncodeToString(salt)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("desktop-tdf", func(t *testing.T) {
		f := strings.Split(strings.TrimPrefix(telegramDesktopPublishedRecord, "$telegram$"), "*")
		salt, _ := hex.DecodeString(f[2])
		key, _ := hex.DecodeString(f[3])
		actual := make([]byte, 4+32+4+288)
		binary.BigEndian.PutUint32(actual[:4], 32)
		copy(actual[4:36], salt)
		binary.BigEndian.PutUint32(actual[36:40], 288)
		copy(actual[40:], key)
		version := make([]byte, 4)
		binary.LittleEndian.PutUint32(version, 1003008)
		checkInput := append([]byte(nil), actual...)
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(actual)))
		checkInput = append(checkInput, size[:]...)
		checkInput = append(checkInput, version...)
		checkInput = append(checkInput, []byte("TDF$")...)
		checksum := md5.Sum(checkInput)
		file := append([]byte("TDF$"), version...)
		file = append(file, actual...)
		file = append(file, checksum[:]...)
		got, err := extractTelegramRecords(extractorFixture(t, "map0", file))
		if err != nil || len(got) != 1 || got[0] != telegramDesktopPublishedRecord {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}
