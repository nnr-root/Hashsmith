package smith

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// As next door, each container is REBUILT from the record John's own format
// test carries, so the bytes the extractor reads came from a real file that
// really cracked with a known password.

func TestExtractLotusRoundTrip(t *testing.T) {
	record, password := johnVector(t, "lotus85")
	blob := mustHex(t, record)

	file := make([]byte, lotusBlobStart+len(blob))
	binary.LittleEndian.PutUint16(file[lotusBlobLengthAt:], uint16(len(blob)))
	copy(file[lotusBlobStart:], blob)

	got, err := extractLotusRecords(writeFixture(t, "user.id", file))
	if err != nil {
		t.Fatalf("extractLotusRecords: %v", err)
	}
	if len(got) != 1 || !strings.EqualFold(got[0], record) {
		t.Fatalf("lotus2smith did not reproduce John's record.\n got: %s\nwant: %s", got[0], record)
	}
	mustCrack(t, "lotus85", got[0], password)
}

func TestExtractAndOTPRoundTrip(t *testing.T) {
	record, password := johnVector(t, "andOTP $andotp$")
	f := strings.Split(strings.TrimPrefix(record, "$andotp$"), "*")
	file := append(append(mustHex(t, f[1]), mustHex(t, f[2])...), mustHex(t, f[3])...)

	got, err := extractAndOTPRecords(writeFixture(t, "otp_accounts.json.aes", file))
	if err != nil {
		t.Fatalf("extractAndOTPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("andotp2smith did not reproduce John's record.\n got: %s\nwant: %s", got[0], record)
	}
	mustCrack(t, "andotp", got[0], password)
}

func TestExtractDashlaneRoundTrip(t *testing.T) {
	record, password := johnVector(t, "dashlane $dashlane$")
	f := strings.Split(strings.TrimPrefix(record, "$dashlane$"), "*")
	file := mustHex(t, f[1])
	if f[0] == "1" {
		file = append(file, []byte("KWC3")...)
	}
	file = append(file, mustHex(t, f[3])...)

	got, err := extractDashlaneRecords(writeFixture(t, "localSettings.aes", file))
	if err != nil {
		t.Fatalf("extractDashlaneRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("dashlane2smith did not reproduce John's record.\n got: %.60s...\nwant: %.60s...", got[0], record)
	}
	mustCrack(t, "dashlane", got[0], password)

	// The exported "secure archive" spelling wraps the same bytes in base64
	// on the line after a marker, and must reach the same record.
	archive := "Dashlane Secure Archive\nData BEGIN\n" +
		base64.StdEncoding.EncodeToString(file) + "\nData END\n"
	fromArchive, err := extractDashlaneRecords(writeFixture(t, "archive.txt", []byte(archive)))
	if err != nil || len(fromArchive) != 1 || fromArchive[0] != record {
		t.Fatalf("the secure-archive spelling gave %v, %v", fromArchive, err)
	}
}

func TestExtractPadlockRoundTrip(t *testing.T) {
	record, password := johnVector(t, "Padlock $padlock$")
	f := strings.Split(strings.TrimPrefix(record, "$padlock$"), "$")
	iterations, _ := strconv.Atoi(f[1])
	tagLen, _ := strconv.Atoi(f[2])
	b64 := func(h string) string { return base64.StdEncoding.EncodeToString(mustHex(t, h)) }

	container := fmt.Sprintf(
		`{"cipher":"AES","mode":"ccm","ts":%d,"iter":%d,"keySize":256,`+
			`"salt":"%s","iv":"%s","adata":"%s","ct":"%s"}`,
		tagLen, iterations, b64(f[4]), b64(f[5]), b64(f[7]), b64(f[9]))

	got, err := extractPadlockRecords(writeFixture(t, "padlock.json", []byte(container)))
	if err != nil {
		t.Fatalf("extractPadlockRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("padlock2smith did not reproduce John's record.\n got: %s\nwant: %s", got[0], record)
	}
	mustCrack(t, "padlock", got[0], password)
}

// Anything but AES-256-CCM must be refused rather than passed through, because
// the verifier would read the record as AES-CCM and answer it wrongly.
func TestExtractPadlockRefusesOtherCiphers(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`{"cipher":"3DES","mode":"ccm","keySize":256}`, "not AES"},
		{`{"cipher":"AES","mode":"gcm","keySize":256}`, "not ccm"},
		{`{"cipher":"AES","mode":"ccm","keySize":128}`, "not 256"},
	} {
		_, err := extractPadlockRecords(writeFixture(t, "p.json", []byte(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s should be refused with %q, got %v", c.body, c.want, err)
		}
	}
}

func TestExtractGELIRoundTrip(t *testing.T) {
	record, password := johnVector(t, "geli $geli$")
	f := strings.Split(strings.TrimPrefix(record, "$geli$"), "$")
	num := func(s string) int { n, _ := strconv.Atoi(s); return n }
	version, ealgo, keyLen, aalgo, keys, iterations :=
		num(f[1]), num(f[2]), num(f[3]), num(f[4]), num(f[5]), num(f[6])

	var md bytes.Buffer
	magic := make([]byte, 16)
	copy(magic, geliMagic)
	md.Write(magic)
	le32 := func(v uint32) { var b [4]byte; binary.LittleEndian.PutUint32(b[:], v); md.Write(b[:]) }
	le16 := func(v uint16) { var b [2]byte; binary.LittleEndian.PutUint16(b[:], v); md.Write(b[:]) }
	le32(uint32(version))
	le32(0) // md_flags
	le16(uint16(ealgo))
	le16(uint16(keyLen))
	if version != 0 {
		le16(uint16(aalgo))
	}
	md.Write(make([]byte, 8)) // md_provsize
	le32(512)                 // md_sectorsize
	md.WriteByte(byte(keys))
	le32(uint32(iterations))
	md.Write(mustHex(t, f[7]))
	md.Write(mustHex(t, f[8]))
	md.Write(make([]byte, 16)) // md_hash

	// The metadata lives in the provider's last sector, so the fixture is a
	// disk-shaped file with the block at its end.
	file := make([]byte, 4096)
	copy(file[len(file)-md.Len():], md.Bytes())

	got, err := extractGELIRecords(writeFixture(t, "geli.img", file))
	if err != nil {
		t.Fatalf("extractGELIRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("geli2smith did not reproduce John's record.\n got: %.70s...\nwant: %.70s...", got[0], record)
	}
	mustCrack(t, "geli", got[0], password)
}

func TestExtractOpenBSDSoftraidRoundTrip(t *testing.T) {
	record, password := johnVector(t, "OpenBSD-SoftRAID $openbsd-softraid$")
	f := strings.Split(strings.TrimPrefix(record, "$openbsd-softraid$"), "$")
	iterations, _ := strconv.Atoi(f[0])

	h := make([]byte, 2696)
	copy(h[0:], softraidMagic)
	copy(h[72:], "SR CRYPTO")
	h[260] = 1
	h[284] = 2
	copy(h[364:2412], mustHex(t, f[2]))
	binary.LittleEndian.PutUint32(h[2416:], softraidKDFPKCS5)
	binary.LittleEndian.PutUint32(h[2420:], uint32(iterations))
	copy(h[2424:2552], mustHex(t, f[1]))
	copy(h[2676:2696], mustHex(t, f[3]))

	// The header does not start at offset zero in a real image.
	file := append(make([]byte, 512), h...)

	got, err := extractOpenBSDSoftraidRecords(writeFixture(t, "softraid.img", file))
	if err != nil {
		t.Fatalf("extractOpenBSDSoftraidRecords: %v", err)
	}
	// John's vector predates the KDF-type field, so the records differ by
	// that one field. What must hold is that the record cracks.
	if len(got) != 1 || !strings.HasPrefix(got[0], record) {
		t.Fatalf("openbsd_softraid2smith\n got: %.70s...\nwant a record beginning %.70s...", got[0], record)
	}
	mustCrack(t, "openbsd-softraid", got[0], password)
}

func TestExtractEnpass(t *testing.T) {
	head := make([]byte, 2048)
	for i := range head {
		head[i] = byte(i)
	}
	got, err := extractEnpassRecords(writeFixture(t, "vault.enpassdb", head))
	if err != nil {
		t.Fatalf("extractEnpassRecords: %v", err)
	}
	want := fmt.Sprintf("$enpass$1$100000$%s", hex.EncodeToString(head[:1024]))
	if len(got) != 1 || got[0] != want {
		t.Fatalf("enpass2smith\n got: %.40s...\nwant: %.40s...", got[0], want)
	}
}

func TestExtractFileZilla(t *testing.T) {
	const password = "openwall"
	md5Digest := md5HexOf(password)
	salt := "abc:def"
	shaSum := sha512.Sum512([]byte(password + salt))
	sha := hex.EncodeToString(shaSum[:])

	doc := `<?xml version="1.0"?><FileZillaServer><Users>` +
		`<User Name="md5user"><Option Name="Pass">` + strings.ToUpper(md5Digest) + `</Option></User>` +
		`<User Name="shauser"><Option Name="Pass">` + sha + `</Option>` +
		`<Option Name="Salt">` + salt + `</Option></User>` +
		`<User Name="nopass"></User></Users></FileZillaServer>`

	got, err := extractFileZillaRecords(writeFixture(t, "FileZilla Server.xml", []byte(doc)))
	if err != nil {
		t.Fatalf("extractFileZillaRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("filezilla2smith returned %d records, want 2: %v", len(got), got)
	}
	if got[0] != "$dynamic_0$"+md5Digest {
		t.Errorf("the MD5 user's record is %q", got[0])
	}
	// The salt holds a colon, which is exactly why it goes in as hex.
	if !strings.HasSuffix(got[1], "$HEX$"+hex.EncodeToString([]byte(salt))) {
		t.Errorf("the salted user's record lost its salt: %q", got[1])
	}
	mustCrack(t, "dynamic", got[0], password)
	mustCrack(t, "dynamic", got[1], password)
}

func TestExtractMcAfeeEPO(t *testing.T) {
	const password = "openwall"
	seed := []byte("SEED")
	// dynamic_24 is sha1($p.$s): the password comes FIRST and the seed is
	// the salt, even though the blob stores the seed after the digest.
	sum := sha1.Sum(append([]byte(password), seed...))
	blob := append(append([]byte(nil), sum[:]...), seed...)

	// Only the value is URL-encoded in a real export, and "+" is the
	// character that matters: base64 emits it and a raw "+" in a query
	// value decodes to a space.
	line := "admin,auth:pwd?pwd=" +
		strings.ReplaceAll(base64.StdEncoding.EncodeToString(blob), "+", "%2B") + ",other\n"

	got, err := extractMcAfeeEPORecords(writeFixture(t, "OrionUsers.csv", []byte(line)))
	if err != nil {
		t.Fatalf("extractMcAfeeEPORecords: %v", err)
	}
	want := "$dynamic_24$" + hex.EncodeToString(sum[:]) + "$HEX$" + hex.EncodeToString(seed)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("mcafee_epo2smith\n got: %v\nwant: %s", got, want)
	}
	mustCrack(t, "dynamic", got[0], password)
}

func TestExtractStarOfficeRoundTrip(t *testing.T) {
	record, password := johnVector(t, "ODF $sxc$")
	f := strings.Split(strings.TrimPrefix(record, "$sxc$*"), "*")
	iterations := f[2]
	checksum, iv, salt := mustHex(t, f[4]), mustHex(t, f[6]), mustHex(t, f[8])
	original, _ := strconv.Atoi(f[9])
	content := mustHex(t, f[11])

	manifest := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">` +
		`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.sun.xml.calc"/>` +
		`<manifest:file-entry manifest:full-path="content.xml" manifest:size="` +
		strconv.Itoa(original) + `">` +
		`<manifest:encryption-data manifest:checksum-type="SHA1/1K" manifest:checksum="` +
		base64.StdEncoding.EncodeToString(checksum) + `">` +
		`<manifest:algorithm manifest:algorithm-name="Blowfish CFB" manifest:initialisation-vector="` +
		base64.StdEncoding.EncodeToString(iv) + `"/>` +
		`<manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:salt="` +
		base64.StdEncoding.EncodeToString(salt) + `" manifest:iteration-count="` + iterations + `"/>` +
		`</manifest:encryption-data></manifest:file-entry></manifest:manifest>`

	path := filepath.Join(t.TempDir(), "secret.sxc")
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fh)
	for _, e := range []struct {
		name string
		body []byte
	}{
		{"META-INF/manifest.xml", []byte(manifest)},
		// The document stores the UNPADDED stream; the padding in the
		// record is added by the extractor.
		{"content.xml", content[:original]},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	got, err := extractStarOfficeRecords(path)
	if err != nil {
		t.Fatalf("extractStarOfficeRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("staroffice2smith did not reproduce John's record.\n got: %.90s...\nwant: %.90s...", got[0], record)
	}
	mustCrack(t, "odf", got[0], password)
}
