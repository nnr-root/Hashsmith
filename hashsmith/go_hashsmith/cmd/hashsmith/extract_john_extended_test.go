package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJohnExtendedPublishedVerifiers(t *testing.T) {
	tests := []struct{ typ, password, record string }{
		{"android-backup", "password", androidBackupPublishedRecord},
		{"encfs", "Jupiter", encFSPublishedRecord},
		{"mozilla-nss", "12345678", mozillaPublishedRecord},
		{"apple-secure-notes", "hashcat", "$ASN$*42*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41"},
	}
	for _, tc := range tests {
		t.Run(tc.typ, func(t *testing.T) {
			ok, err := verifyCandidate(tc.password, tc.record, tc.typ, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector failed: ok=%v err=%v", ok, err)
			}
			ok, err = verifyCandidate(tc.password+"!", tc.record, tc.typ, "", "prefix")
			if err != nil || ok {
				t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
			}
			if got := detectHashTypes(tc.record); len(got) != 1 || got[0] != tc.typ {
				t.Fatalf("detection=%v, want [%s]", got, tc.typ)
			}
		})
	}
}

func TestJohnExtendedTextAndXMLExtractors(t *testing.T) {
	t.Run("android-backup", func(t *testing.T) {
		parts := strings.Split(strings.TrimPrefix(androidBackupPublishedRecord, "$ab$"), "*")
		body := "ANDROID BACKUP\n" + parts[0] + "\n1\nAES-256\n" + parts[3] + "\n" + parts[4] + "\n" + parts[2] + "\n" + parts[5] + "\n" + parts[6] + "\n"
		got, err := extractAndroidBackupRecords(extractorFixture(t, "backup.ab", []byte(body)))
		if err != nil || len(got) != 1 || got[0] != androidBackupPublishedRecord {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("encfs", func(t *testing.T) {
		p := strings.Split(strings.TrimPrefix(encFSPublishedRecord, "$encfs$"), "*")
		salt, _ := hex.DecodeString(p[4])
		data, _ := hex.DecodeString(p[6])
		xml := `<boost_serialization><cfg><name>AES</name><keySize>` + p[0] + `</keySize><kdfIterations>` + p[1] +
			`</kdfIterations><saltLen>` + p[3] + `</saltLen><saltData>` + base64.StdEncoding.EncodeToString(salt) +
			`</saltData><encodedKeySize>` + p[5] + `</encodedKeySize><encodedKeyData>` + base64.StdEncoding.EncodeToString(data) +
			`</encodedKeyData></cfg></boost_serialization>`
		got, err := extractEncFSRecords(extractorFixture(t, ".encfs6.xml", []byte(xml)))
		if err != nil || len(got) != 1 || got[0] != encFSPublishedRecord {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("mozilla", func(t *testing.T) {
		p := strings.Split(mozillaPublishedRecord, "*")
		entry, _ := hex.DecodeString(p[4])
		verifier, _ := hex.DecodeString(p[8])
		global, _ := hex.DecodeString(p[10])
		check := make([]byte, 52)
		copy(check[3:23], entry)
		copy(check[36:52], verifier)
		fixture := append(append(append([]byte("prefix"), global...), []byte("global-salt")...), check...)
		fixture = append(fixture, []byte("password-check")...)
		got, err := extractMozillaRecords(extractorFixture(t, "key3.db", fixture))
		want := strings.Replace(mozillaPublishedRecord, "2a864886f70d010c050103", strings.Repeat("00", 11), 1)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("vmx", func(t *testing.T) {
		salt := bytesOf(0x11, 16)
		crypted := bytesOf(0x22, 40)
		line := `encryption.keySafe = "phrase/id/pass2key=PBKDF2-HMAC-SHA-1:cipher=AES-256:rounds=10000:salt=` +
			base64.RawURLEncoding.EncodeToString(salt) + `,` + base64.RawURLEncoding.EncodeToString(crypted) + `,digest"`
		got, err := extractVMXRecords(extractorFixture(t, "machine.vmx", []byte(line)))
		want := "$vmx$0$10000$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(crypted[:32])
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestJohnExtendedDirectoryAndBinaryExtractors(t *testing.T) {
	t.Run("lastpass", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "username"), []byte("USER@example.com\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "iterations"), []byte("5000\n"), 0600); err != nil {
			t.Fatal(err)
		}
		verify := make([]byte, 64)
		copy(verify[32:48], bytesOf(0x11, 16))
		copy(verify[48:64], bytesOf(0x22, 16))
		if err := os.WriteFile(filepath.Join(dir, "verify"), verify, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := extractLastPassRecords(dir)
		want := strings.Repeat("22", 16) + ":5000:user@example.com:" + strings.Repeat("11", 16)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("monero", func(t *testing.T) {
		got, err := extractMoneroRecords(extractorFixture(t, "wallet.keys", []byte("0123456789abcdef")))
		if err != nil || len(got) != 1 || got[0] != "$monero$0*30313233343536373839616263646566" {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("virtualbox", func(t *testing.T) {
		raw := make([]byte, 250)
		copy(raw, "VBOX")
		raw[5] = 1
		binary.LittleEndian.PutUint32(raw[70:74], 32)
		copy(raw[74:106], bytesOf(0xaa, 32))
		binary.LittleEndian.PutUint32(raw[106:110], 32)
		copy(raw[110:142], bytesOf(0xbb, 32))
		binary.LittleEndian.PutUint32(raw[142:146], 20000)
		copy(raw[146:178], bytesOf(0xcc, 32))
		binary.LittleEndian.PutUint32(raw[178:182], 260000)
		binary.LittleEndian.PutUint32(raw[182:186], 64)
		copy(raw[186:218], bytesOf(0xdd, 32))
		xml := `<VirtualBox><Property name="CRYPT/KeyStore" value="` + base64.StdEncoding.EncodeToString(raw) + `"/></VirtualBox>`
		got, err := extractVirtualBoxRecords(extractorFixture(t, "machine.vbox", []byte(xml)))
		want := "$vbox$0$260000$" + strings.Repeat("cc", 32) + "$8$" + strings.Repeat("dd", 32) + "$20000$" + strings.Repeat("bb", 32) + "$" + strings.Repeat("aa", 32)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("dmg-v1", func(t *testing.T) {
		h := make([]byte, 1276)
		binary.BigEndian.PutUint32(h[48:52], 1000)
		binary.BigEndian.PutUint32(h[52:56], 8)
		copy(h[56:64], []byte("12345678"))
		binary.BigEndian.PutUint32(h[136:140], 16)
		copy(h[140:156], bytesOf(0x11, 16))
		binary.BigEndian.PutUint32(h[436:440], 20)
		copy(h[440:460], bytesOf(0x22, 20))
		copy(h[len(h)-8:], "cdsaencr")
		got, err := extractDMGRecords(extractorFixture(t, "disk.dmg", h))
		want := "$dmg$1*8*3132333435363738*16*" + strings.Repeat("11", 16) + "*20*" + strings.Repeat("22", 20) + "*1000"
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("dmg-v2", func(t *testing.T) {
		h := make([]byte, 264+12288)
		copy(h[:8], "encrcdsa")
		binary.BigEndian.PutUint64(h[56:64], 12288)
		binary.BigEndian.PutUint64(h[64:72], 264)
		binary.BigEndian.PutUint32(h[104:108], 2000)
		binary.BigEndian.PutUint32(h[108:112], 8)
		copy(h[112:120], []byte("12345678"))
		copy(h[148:180], bytesOf(0x33, 32))
		binary.BigEndian.PutUint32(h[196:200], 48)
		copy(h[200:248], bytesOf(0x44, 48))
		got, err := extractDMGRecords(extractorFixture(t, "disk-v2.dmg", h))
		if err != nil || len(got) != 1 || !strings.HasPrefix(got[0], "$dmg$2*8*3132333435363738*32*"+strings.Repeat("33", 32)+"*48*"+strings.Repeat("44", 48)+"*1*8192*") {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("bitlocker", func(t *testing.T) {
		image := make([]byte, 0x2000)
		copy(image[3:11], "-FVE-FS-")
		binary.LittleEndian.PutUint64(image[0xb0:0xb8], 0x1000)
		metadata := image[0x1000:]
		salt := bytesOf(0x44, 16)
		vmk := make([]byte, 108)
		binary.LittleEndian.PutUint16(vmk[26:28], 0x2000)
		binary.LittleEndian.PutUint16(vmk[28:30], 28)
		binary.LittleEndian.PutUint16(vmk[32:34], 3)
		copy(vmk[40:56], salt)
		binary.LittleEndian.PutUint16(vmk[56:58], 52)
		binary.LittleEndian.PutUint16(vmk[60:62], 5)
		copy(vmk[64:108], bytesOf(0x55, 44))
		binary.LittleEndian.PutUint16(metadata[112:114], 116)
		binary.LittleEndian.PutUint16(metadata[116:118], 8)
		copy(metadata[120:228], vmk)
		binary.LittleEndian.PutUint32(metadata[64:68], 228)
		got, err := extractBitLockerRecords(extractorFixture(t, "volume.img", image), 0)
		if err != nil || len(got) != 2 || !strings.HasPrefix(got[0], "$bitlocker$0$16$"+hex.EncodeToString(salt)) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestJohnExtendedSQLiteExtractors(t *testing.T) {
	t.Run("bitcoin", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wallet.dat")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`CREATE TABLE main (key BLOB, value BLOB)`); err != nil {
			t.Fatal(err)
		}
		key := append([]byte{4}, []byte("mkey")...)
		key = append(key, 1, 0, 0, 0)
		value := append([]byte{48}, bytesOf(0x11, 48)...)
		value = append(value, 8)
		value = append(value, bytesOf(0x22, 8)...)
		var trailer [8]byte
		binary.LittleEndian.PutUint32(trailer[4:], 25000)
		value = append(value, trailer[:]...)
		if _, err = db.Exec(`INSERT INTO main(key,value) VALUES(?,?)`, key, value); err != nil {
			t.Fatal(err)
		}
		db.Close()
		got, err := extractBitcoinRecords(path)
		want := "$bitcoin$64$" + strings.Repeat("11", 32) + "$16$" + strings.Repeat("22", 8) + "$25000$2$00$2$00"
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("apple-notes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "NoteStore.sqlite")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER, ZCRYPTOITERATIONCOUNT INTEGER, ZCRYPTOSALT BLOB, ZCRYPTOWRAPPEDKEY BLOB, ZCRYPTOVERIFIER BLOB)`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES(?,?,?,?,?)`, 42, 20000, bytesOf(0x11, 16), bytesOf(0x22, 24), nil)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
		got, err := extractAppleNotesRecords(path)
		want := "$ASN$*42*20000*" + strings.Repeat("11", 16) + "*" + strings.Repeat("22", 24)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestBitcoinLegacyBerkeleyDBExtractor(t *testing.T) {
	fixture := make([]byte, 512)
	binary.LittleEndian.PutUint32(fixture[12:16], 0x00053162)
	value := []byte{48}
	value = append(value, bytesOf(0x11, 48)...)
	value = append(value, 8)
	value = append(value, bytesOf(0x22, 8)...)
	var word [4]byte
	binary.LittleEndian.PutUint32(word[:], 0)
	value = append(value, word[:]...)
	binary.LittleEndian.PutUint32(word[:], 25000)
	value = append(value, word[:]...)
	value = append(value, 0) // empty derivation-parameters vector
	copy(fixture[128:], value)

	got, err := extractBitcoinRecords(extractorFixture(t, "wallet.dat", fixture))
	want := "$bitcoin$64$" + strings.Repeat("11", 32) + "$16$" + strings.Repeat("22", 8) + "$25000$2$00$2$00"
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, %v", got, err)
	}
}
