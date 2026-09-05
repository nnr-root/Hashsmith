package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSniffKeePassKDBX4(t *testing.T) {
	// KDBX signature: 0x9AA2D903 0xB54BFB67, then minor/major version words.
	head := []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x00, 0x00, 0x04, 0x00}
	head = append(head, make([]byte, 64)...)
	p := writeTemp(t, "Database.kdbx", head)

	d, ev, ok := sniffContainer(p)
	if !ok {
		t.Fatal("KDBX file was not recognized")
	}
	if d.name != "keepass2smith" {
		t.Errorf("routed to %s, want keepass2smith", d.name)
	}
	if !strings.Contains(string(ev), "KDBX") {
		t.Errorf("evidence = %q, want it to mention KDBX", ev)
	}
}

func TestSniffZip(t *testing.T) {
	p := writeTemp(t, "archive.zip", append([]byte("PK\x03\x04"), make([]byte, 64)...))
	d, _, ok := sniffContainer(p)
	if !ok || d.name != "zip2smith" {
		t.Fatalf("zip routed to %v (ok=%v), want zip2smith", d, ok)
	}
}

func TestSniffPDF(t *testing.T) {
	p := writeTemp(t, "doc.pdf", append([]byte("%PDF-1.7\n"), make([]byte, 64)...))
	d, _, ok := sniffContainer(p)
	if !ok || d.name != "pdf2smith" {
		t.Fatalf("pdf routed to %v (ok=%v), want pdf2smith", d, ok)
	}
}

func TestSniffRejectsPlainText(t *testing.T) {
	p := writeTemp(t, "hashes.txt", []byte("5f4dcc3b5aa765d61d8327deb882cf99\n"))
	if _, _, ok := sniffContainer(p); ok {
		t.Error("a text file of hashes must not be treated as a container")
	}
}

func TestContainerOutputNamesTheExtractorCommand(t *testing.T) {
	d, _ := findExtractor("keepass2smith")
	out := renderContainerIdentification("Database.kdbx", d, "KDBX 4.0, KDF Argon2d")
	if !strings.Contains(out, "hashsmith keepass2smith -f Database.kdbx") {
		t.Errorf("output missing the runnable extractor command\n---\n%s", out)
	}
}

func TestSniffPKCS12Recognized(t *testing.T) {
	// PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, ... }.
	// version 3 is the only value PKCS#12 uses.
	head := []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03}
	head = append(head, make([]byte, 64)...)
	p := writeTemp(t, "keystore.pfx", head)

	d, _, ok := sniffContainer(p)
	if !ok || d.name != "pfx2smith" {
		t.Fatalf("pfx routed to %v (ok=%v), want pfx2smith", d, ok)
	}
}

func TestSniffPKCS12RejectsGenericDER(t *testing.T) {
	// Same {0x30, 0x82} SEQUENCE-with-2-byte-length prefix any large DER
	// structure starts with (e.g. an X.509 certificate, whose first child is
	// another SEQUENCE, not the version INTEGER PKCS#12 requires). A loose
	// sniffer keyed only on {0x30, 0x82} would wrongly call this a PFX.
	head := []byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xF0}
	head = append(head, make([]byte, 64)...)
	p := writeTemp(t, "cert.der", head)

	if _, _, ok := sniffContainer(p); ok {
		t.Error("a generic DER SEQUENCE must not be treated as a PKCS#12 keystore")
	}
}

func TestSniffCoverageIsReported(t *testing.T) {
	with, total := sniffCoverage()
	if total != len(universalExtractorRegistry) {
		t.Errorf("total = %d, want %d", total, len(universalExtractorRegistry))
	}
	if with == 0 {
		t.Error("no extractor implements sniff")
	}
	t.Logf("sniff coverage: %d/%d extractors", with, total)
}
