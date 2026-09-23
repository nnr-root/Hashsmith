package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// All three containers hide their structure inside a file whose beginning
// belongs to something else, so each fixture puts the structure at a non-zero
// offset behind filler. A reader that assumed offset zero would pass a test
// that did not.

func TestExtractPGPSDARoundTrip(t *testing.T) {
	record, password := johnVector(t, "pgpsda $pgpsda$")
	f := strings.Split(strings.TrimPrefix(record, "$pgpsda$"), "*")
	iterations, _ := strconv.Atoi(f[1])

	header := make([]byte, pgpSDAHeaderSize)
	copy(header, pgpSDAMagic)
	binary.LittleEndian.PutUint32(header[6:], 64) // offset, inside the file
	copy(header[26:34], mustHex(t, f[2]))         // salt
	binary.LittleEndian.PutUint16(header[34:], uint16(iterations))
	copy(header[36:44], mustHex(t, f[3])) // check bytes

	// A real SDA is an executable with this bolted on the end.
	file := append(bytes.Repeat([]byte{0x4d, 0x5a}, 512), header...)

	got, err := extractPGPSDARecords(writeFixture(t, "archive.sda", file))
	if err != nil {
		t.Fatalf("extractPGPSDARecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("pgpsda2smith\n got: %v\nwant: %s", got, record)
	}
	mustCrack(t, "pgpsda", got[0], password)
}

func TestExtractPGPDiskRoundTrip(t *testing.T) {
	record, password := johnVector(t, "pgpdisk $pgpdisk$")
	f := strings.Split(strings.TrimPrefix(record, "$pgpdisk$"), "*")
	algorithm, _ := strconv.Atoi(f[1])
	iterations, _ := strconv.Atoi(f[2])

	const userAt = 8192
	main := make([]byte, pgpDiskMainSize)
	copy(main[0:4], "PGPd")
	copy(main[4:8], "MAIN")
	binary.LittleEndian.PutUint64(main[16:], userAt) // nextHeaderOffset
	main[32] = 7                                     // majorVersion
	binary.LittleEndian.PutUint32(main[60:], uint32(algorithm))
	copy(main[64:80], mustHex(t, f[3])) // salt

	user := make([]byte, pgpDiskUserSize)
	copy(user[0:4], "USER")
	copy(user[4:8], "SYMM")
	copy(user[32:160], "alice")
	copy(user[288:304], mustHex(t, f[4])) // check bytes
	binary.LittleEndian.PutUint16(user[304:], uint16(iterations))

	// The MAIN header sits a little way in, and the USER record is far
	// enough away that only following the pointer finds it.
	file := make([]byte, userAt+pgpDiskUserSize)
	copy(file[512:], main)
	copy(file[userAt:], user)

	got, err := extractPGPDiskRecords(writeFixture(t, "volume.pgd", file))
	if err != nil {
		t.Fatalf("extractPGPDiskRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("pgpdisk2smith\n got: %v\nwant: %s", got, record)
	}
	mustCrack(t, "pgpdisk", got[0], password)
}

// A disk with two users gives two records over the same salt: they are two
// passwords to one volume and either opens it.
func TestExtractPGPDiskEmitsEveryUser(t *testing.T) {
	record, _ := johnVector(t, "pgpdisk $pgpdisk$")
	f := strings.Split(strings.TrimPrefix(record, "$pgpdisk$"), "*")
	algorithm, _ := strconv.Atoi(f[1])

	const userAt = 4096
	main := make([]byte, pgpDiskMainSize)
	copy(main[0:4], "PGPd")
	copy(main[4:8], "MAIN")
	binary.LittleEndian.PutUint64(main[16:], userAt)
	main[32] = 6
	binary.LittleEndian.PutUint32(main[60:], uint32(algorithm))
	copy(main[64:80], mustHex(t, f[3]))

	file := make([]byte, userAt+2*pgpDiskUserSize)
	copy(file, main)
	for k := 0; k < 2; k++ {
		user := make([]byte, pgpDiskUserSize)
		copy(user[0:4], "USER")
		copy(user[4:8], "SYMM")
		copy(user[288:304], mustHex(t, f[4]))
		binary.LittleEndian.PutUint16(user[304:], uint16(1000+k))
		copy(file[userAt+k*pgpDiskUserSize:], user)
	}

	got, err := extractPGPDiskRecords(writeFixture(t, "two.pgd", file))
	if err != nil {
		t.Fatalf("extractPGPDiskRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want one per user: %v", len(got), got)
	}
	if !strings.Contains(got[0], "*1000*") || !strings.Contains(got[1], "*1001*") {
		t.Errorf("each user's own iteration count should survive: %v", got)
	}
}

func TestExtractPGPWDERoundTrip(t *testing.T) {
	record, password := johnVector(t, "pgpwde $pgpwde$")
	f := strings.Split(strings.TrimPrefix(record, "$pgpwde$"), "*")
	symmAlg, _ := strconv.Atoi(f[1])
	s2kType, _ := strconv.Atoi(f[2])
	iterations, _ := strconv.Atoi(f[3])

	u := make([]byte, pgpWDEUserInfoSize)
	binary.LittleEndian.PutUint16(u[0:], 512) // size
	u[2] = 0                                  // version
	u[3] = pgpWDEUserWithSym
	binary.LittleEndian.PutUint32(u[4:], pgpWDEMagic)
	u[8] = 1 // totalRecords
	u[9] = 0 // currentRecord
	u[28] = byte(symmAlg)
	copy(u[34:162], "alice")
	u[162] = byte(s2kType)
	binary.LittleEndian.PutUint32(u[163:], uint32(iterations))
	copy(u[170:186], mustHex(t, f[4]))
	copy(u[186:], mustHex(t, f[5]))

	file := make([]byte, 65536+pgpWDEUserInfoSize)
	copy(file[65536:], u)

	got, err := extractPGPWDERecords(writeFixture(t, "disk.raw", file))
	if err != nil {
		t.Fatalf("extractPGPWDERecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("pgpwde2smith\n got: %.60s...\nwant: %.60s...", got[0], record)
	}
	mustCrack(t, "pgpwde", got[0], password)
}

// A record kind other than 0x08 holds a token, a public key or a TPM blob, so
// there is no passphrase behind it and no record to write.
func TestExtractPGPWDESkipsOtherUserKinds(t *testing.T) {
	u := make([]byte, pgpWDEUserInfoSize)
	binary.LittleEndian.PutUint16(u[0:], 512)
	u[3] = 0x0A // kPGPdiskUserWithPubType
	binary.LittleEndian.PutUint32(u[4:], pgpWDEMagic)
	if _, err := extractPGPWDERecords(writeFixture(t, "pub.raw", u)); err == nil {
		t.Error("a public-key user record has no passphrase and should yield nothing")
	}
}

// ── LibreOffice ──────────────────────────────────────────────────────────────

// buildODFPackage writes a minimal OpenDocument package: a manifest naming how
// content.xml was encrypted, and content.xml itself.
func buildODFPackage(t *testing.T, name, manifest string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
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
		{"content.xml", content},
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
	return path
}

func odfManifestXML(algorithm, checksumType, startKey, iterations, keySize, checksum, iv, salt string) string {
	start := ""
	if startKey != "" {
		start = `<manifest:start-key-generation manifest:start-key-generation-name="` + startKey + `"/>`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">` +
		`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>` +
		`<manifest:file-entry manifest:full-path="content.xml" manifest:size="1024">` +
		`<manifest:encryption-data manifest:checksum-type="` + checksumType + `" manifest:checksum="` + checksum + `">` +
		`<manifest:algorithm manifest:algorithm-name="` + algorithm + `" manifest:initialisation-vector="` + iv + `"/>` +
		start +
		`<manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:key-size="` + keySize +
		`" manifest:salt="` + salt + `" manifest:iteration-count="` + iterations + `"/>` +
		`</manifest:encryption-data></manifest:file-entry></manifest:manifest>`
}

func TestExtractLibreOfficeRoundTrip(t *testing.T) {
	record, password := johnVector(t, "ODF $odf$")
	f := strings.Split(strings.TrimPrefix(record, "$odf$*"), "*")
	b64 := func(h string) string { return base64.StdEncoding.EncodeToString(mustHex(t, h)) }

	algorithm, checksumName := "Blowfish CFB", "SHA1/1K"
	startKey := "SHA1"
	if f[0] == "1" {
		algorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	}
	if f[1] == "1" {
		checksumName, startKey = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k", "http://www.w3.org/2000/09/xmldsig#sha256"
	}
	manifest := odfManifestXML(algorithm, checksumName, startKey, f[2], f[3],
		b64(f[4]), b64(f[6]), b64(f[8]))

	path := buildODFPackage(t, "secret.odt", manifest, mustHex(t, f[10]))
	got, err := extractLibreOfficeRecords(path)
	if err != nil {
		t.Fatalf("extractLibreOfficeRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("libreoffice2smith\n got: %.80s...\nwant: %.80s...", got[0], record)
	}
	mustCrack(t, "odf", got[0], password)
}

// A document naming SHA-1 for its checksum and SHA-256 for its start key
// describes a derivation nothing implements, so it must be refused rather than
// turned into a record that cannot crack.
func TestExtractLibreOfficeRefusesMismatchedDigests(t *testing.T) {
	b := base64.StdEncoding.EncodeToString(make([]byte, 16))
	manifest := odfManifestXML("Blowfish CFB", "SHA1/1K",
		"http://www.w3.org/2000/09/xmldsig#sha256", "1024", "16", b, b, b)
	path := buildODFPackage(t, "bad.odt", manifest, []byte("x"))
	_, err := extractLibreOfficeRecords(path)
	if err == nil || !strings.Contains(err.Error(), "different digests") {
		t.Fatalf("a mismatched pair should be refused by name, got %v", err)
	}
}

// ODF 1.2 can encrypt the whole package as one blob, which carries no per-part
// checksum at all.
func TestExtractLibreOfficeRefusesWholePackage(t *testing.T) {
	manifest := `<?xml version="1.0"?>` +
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">` +
		`<manifest:file-entry manifest:full-path="encrypted-package"/>` +
		`<manifest:file-entry manifest:full-path="content.xml"/>` +
		`</manifest:manifest>`
	path := buildODFPackage(t, "whole.odt", manifest, []byte("x"))
	_, err := extractLibreOfficeRecords(path)
	if err == nil || !strings.Contains(err.Error(), "whole-package") {
		t.Fatalf("whole-package encryption should be refused by name, got %v", err)
	}
}
