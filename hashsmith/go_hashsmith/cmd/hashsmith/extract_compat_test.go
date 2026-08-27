package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func extractorFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractorRegistryIsUniqueAndRoutable(t *testing.T) {
	if got := len(universalExtractorRegistry); got != 47 {
		t.Fatalf("extractor registry has %d entries, want 47", got)
	}
	seen := map[string]bool{}
	for _, d := range universalExtractorRegistry {
		if d.name == "" || d.input == "" || d.formats == "" || d.run == nil {
			t.Fatalf("incomplete extractor definition: %#v", d)
		}
		for _, name := range append([]string{d.name}, d.aliases...) {
			if seen[name] {
				t.Fatalf("duplicate extractor name or alias %q", name)
			}
			seen[name] = true
			if got, ok := findExtractor(name); !ok || got.name != d.name {
				t.Fatalf("cannot resolve %q to %q", name, d.name)
			}
		}
	}
}

func TestExtractorStructuredFormats(t *testing.T) {
	t.Run("1password-agile", func(t *testing.T) {
		raw := append([]byte("Salted__12345678"), make([]byte, 32)...)
		data := `{"list":[{"data":"` + base64.StdEncoding.EncodeToString(raw) + `","iterations":2000}]}`
		got, err := extractOnePasswordRecords(extractorFixture(t, "encryptionKeys.js", []byte(data)))
		want := "2000:3132333435363738:" + strings.Repeat("00", 32)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})

	t.Run("ansible", func(t *testing.T) {
		path := extractorFixture(t, "vault.yml", []byte("$ANSIBLE_VAULT;1.1;AES256\n30300a31310a3232\n"))
		got, err := extractAnsibleRecords(path)
		if err != nil || len(got) != 1 || got[0] != "$ansible$0*0*00*11*22" {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("ethereum-pbkdf2", func(t *testing.T) {
		data := `{"Crypto":{"cipher":"aes-128-ctr","ciphertext":"aabb","mac":"ccdd","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","salt":"0011"}}}`
		got, err := extractEthereumRecords(extractorFixture(t, "key.json", []byte(data)))
		want := "$ethereum$p*1024*0011*aabb*ccdd"
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})

	t.Run("blockchain", func(t *testing.T) {
		payload := base64.StdEncoding.EncodeToString(make([]byte, 16))
		data := `{"payload":"` + payload + `","pbkdf2_iterations":5000}`
		got, err := extractBlockchainRecords(extractorFixture(t, "wallet.aes.json", []byte(data)))
		want := "$blockchain$v2$5000$16$" + strings.Repeat("00", 16)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})

	t.Run("electrum", func(t *testing.T) {
		raw := make([]byte, 64)
		for i := range raw {
			raw[i] = byte(i)
		}
		path := extractorFixture(t, "electrum", []byte(base64.StdEncoding.EncodeToString(raw)))
		got, err := extractElectrumRecords(path)
		want := "$electrum$1*" + hex.EncodeToString(raw[:16]) + "*" + hex.EncodeToString(raw[16:32])
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})

	t.Run("multibit", func(t *testing.T) {
		raw := append([]byte("Salted__"), make([]byte, 40)...)
		path := extractorFixture(t, "wallet.key", []byte(base64.StdEncoding.EncodeToString(raw)))
		got, err := extractMultiBitRecords(path)
		want := "$multibit$1*" + strings.Repeat("00", 8) + "*" + strings.Repeat("00", 32)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})

	t.Run("prosody", func(t *testing.T) {
		data := "iteration_count = 4096;\nsalt = 'salty';\nstored_key = '" + strings.Repeat("ab", 20) + "';\n"
		got, err := extractProsodyRecords(extractorFixture(t, "account.dat", []byte(data)))
		want := "$xmpp-scram$0$4096$5$73616c7479$" + strings.Repeat("ab", 20)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v; want %q", got, err, want)
		}
	})
}

func TestExtractorTextFormats(t *testing.T) {
	t.Run("aix", func(t *testing.T) {
		want := "{ssha256}06$salt$abcdefghijklmnopqrstuv"
		got, err := extractAIXRecords(extractorFixture(t, "passwd", []byte("root:\n\tpassword = "+want+"\n")))
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("aruba", func(t *testing.T) {
		want := "0011223301" + strings.Repeat("ab", 20)
		got, err := extractArubaRecords(extractorFixture(t, "config", []byte("admin:"+want+"\n")))
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("ldif-and-htpasswd", func(t *testing.T) {
		hash := "{SHA}" + base64.StdEncoding.EncodeToString(make([]byte, 20))
		encoded := base64.StdEncoding.EncodeToString([]byte(hash))
		ldif, err := extractLDIFRecords(extractorFixture(t, "users.ldif", []byte("dn: uid=a\nuserPassword:: "+encoded+"\n")))
		if err != nil || len(ldif) != 1 || ldif[0] != hash {
			t.Fatalf("LDIF got %v, %v", ldif, err)
		}
		ht, err := extractHtpasswdRecords(extractorFixture(t, ".htpasswd", []byte("alice:$apr1$salt$kJH8Q5nYki4gLCujDr7LZ.\n")))
		if err != nil || len(ht) != 1 || !strings.HasPrefix(ht[0], "$apr1$") {
			t.Fatalf("htpasswd got %v, %v", ht, err)
		}
	})

	t.Run("hashdump", func(t *testing.T) {
		nt := strings.Repeat("12", 16)
		lm := strings.Repeat("34", 16)
		got, err := extractHashdumpRecords(extractorFixture(t, "ntds.txt", []byte("admin:500:"+lm+":"+nt+":::\n")))
		if err != nil || len(got) != 2 || got[0] != nt || got[1] != lm {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("ike", func(t *testing.T) {
		fields := []string{"00", "11", "22", "33", "44", "55", "66", "77", strings.Repeat("88", 16)}
		want := strings.Join(fields, ":")
		got, err := extractIKERecords(extractorFixture(t, "psk.txt", []byte(want+"\n")))
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("sip", func(t *testing.T) {
		want := "$sip$*srv*cli*user*realm*GET*sip*host**nonce*0001*cnonce*auth*MD5*" + strings.Repeat("a", 32)
		got, err := extractSIPRecords(extractorFixture(t, "sipdump.txt", []byte("label:"+want+"\n")))
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("scan", func(t *testing.T) {
		want := "5f4dcc3b5aa765d61d8327deb882cf99"
		got, err := extractScannedRecords(extractorFixture(t, "app.log", []byte("password_hash=["+want+"]\n")))
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestExtractorBinaryFormats(t *testing.T) {
	raw, err := hex.DecodeString(hccapxHashcatSelfTest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractHCCAPXRecords(extractorFixture(t, "capture.hccapx", raw))
	if err != nil || len(got) != 1 || got[0] != hccapxHashcatSelfTest {
		t.Fatalf("hccapx got %v, %v", got, err)
	}

	header := make([]byte, 700)
	for i := range header {
		header[i] = byte(i)
	}
	got, err = extractCryptHeaderRecords(extractorFixture(t, "volume.tc", header), "truecrypt")
	want := "truecrypt:" + hex.EncodeToString(header[:512])
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("TrueCrypt got %v, %v", got, err)
	}

	var manifest []byte
	appendTag := func(tag string, value []byte) {
		manifest = append(manifest, tag...)
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		manifest = append(manifest, size[:]...)
		manifest = append(manifest, value...)
	}
	appendTag("SALT", bytesOf(0x11, 20))
	var iter [4]byte
	binary.BigEndian.PutUint32(iter[:], 10000)
	appendTag("ITER", iter[:])
	appendTag("WPKY", bytesOf(0x22, 40))
	got, err = extractITunesRecords(extractorFixture(t, "Manifest.plist", manifest))
	want = "$itunes_backup$*9*" + strings.Repeat("22", 40) + "*10000*" + strings.Repeat("11", 20) + "**"
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("iTunes got %v, %v", got, err)
	}
}

func bytesOf(value byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}
