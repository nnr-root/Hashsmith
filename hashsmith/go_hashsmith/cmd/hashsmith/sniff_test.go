package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
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

	d, ev, conf, ok := sniffContainer(p)
	if !ok {
		t.Fatal("KDBX file was not recognized")
	}
	if d.name != "keepass2smith" {
		t.Errorf("routed to %s, want keepass2smith", d.name)
	}
	if !strings.Contains(string(ev), "KDBX") {
		t.Errorf("evidence = %q, want it to mention KDBX", ev)
	}
	if conf != hashid.Certain {
		t.Errorf("confidence = %s, want certain (both signature words matched)", conf)
	}
}

func TestSniffZip(t *testing.T) {
	p := writeTemp(t, "archive.zip", append([]byte("PK\x03\x04"), make([]byte, 64)...))
	d, _, conf, ok := sniffContainer(p)
	if !ok || d.name != "zip2smith" {
		t.Fatalf("zip routed to %v (ok=%v), want zip2smith", d, ok)
	}
	// T16/M11: the bare "PK\x03\x04" local-file-header signature is shared
	// by .docx, .jar, .apk, .odt, .epub and every other ZIP-based container
	// format, so it is no stronger evidence of "this is specifically an
	// encrypted ZIP archive" than office2smith's bare OLE2 header is of
	// "this is specifically an encrypted Office document" — and that one
	// reports Likely (TestSniffOfficeBareHeaderIsLikelyNotCertain). Asserting
	// Certain here overstated what a 4-byte magic actually proves.
	if conf != hashid.Likely {
		t.Errorf("confidence = %s, want likely (bare PK\\x03\\x04 is shared by many ZIP-based formats)", conf)
	}
}

func TestSniffPDF(t *testing.T) {
	p := writeTemp(t, "doc.pdf", append([]byte("%PDF-1.7\n"), make([]byte, 64)...))
	d, _, _, ok := sniffContainer(p)
	if !ok || d.name != "pdf2smith" {
		t.Fatalf("pdf routed to %v (ok=%v), want pdf2smith", d, ok)
	}
}

func TestSniffRejectsPlainText(t *testing.T) {
	p := writeTemp(t, "hashes.txt", []byte("5f4dcc3b5aa765d61d8327deb882cf99\n"))
	if _, _, _, ok := sniffContainer(p); ok {
		t.Error("a text file of hashes must not be treated as a container")
	}
}

func TestContainerOutputNamesTheExtractorCommand(t *testing.T) {
	d, _ := findExtractor("keepass2smith")
	out := renderContainerIdentification("Database.kdbx", d, "KDBX 4.0, KDF Argon2d", hashid.Certain)
	if !strings.Contains(out, "hashsmith keepass2smith -f Database.kdbx") {
		t.Errorf("output missing the runnable extractor command\n---\n%s", out)
	}
}

func TestContainerOutputRendersTheSniffersConfidenceNotALiteral(t *testing.T) {
	d, _ := findExtractor("pfx2smith")
	out := renderContainerIdentification("keystore.pfx", d, "structural match only", hashid.Likely)
	if strings.Contains(out, "certain") {
		t.Errorf("output claims certain for a Likely sniff result\n---\n%s", out)
	}
	if !strings.Contains(out, "likely") {
		t.Errorf("output missing the actual confidence word 'likely'\n---\n%s", out)
	}
}

func TestSniffPKCS12Recognized(t *testing.T) {
	// PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, ... }.
	// version 3 is the only value PKCS#12 uses.
	head := []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03}
	head = append(head, make([]byte, 64)...)
	p := writeTemp(t, "keystore.pfx", head)

	d, _, conf, ok := sniffContainer(p)
	if !ok || d.name != "pfx2smith" {
		t.Fatalf("pfx routed to %v (ok=%v), want pfx2smith", d, ok)
	}
	// Only the outer SEQUENCE + version INTEGER were checked, not the
	// ContentInfo that follows, so this must not claim Certain.
	if conf != hashid.Likely {
		t.Errorf("confidence = %s, want likely (structural match only, not a full ASN.1 decode)", conf)
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

	if _, _, _, ok := sniffContainer(p); ok {
		t.Error("a generic DER SEQUENCE must not be treated as a PKCS#12 keystore")
	}
}

func TestSniffOfficeBareHeaderIsLikelyNotCertain(t *testing.T) {
	// The bare OLE2/CFBF magic is shared by .msi, .msg, Thumbs.db and
	// unencrypted legacy Office documents, so without a confirmed
	// EncryptionInfo/EncryptedPackage stream this must not claim Certain.
	head := append([]byte{0xD0, 0xCF, 0x11, 0xE0}, make([]byte, 64)...)
	p := writeTemp(t, "installer.msi", head)

	d, _, conf, ok := sniffContainer(p)
	if !ok || d.name != "office2smith" {
		t.Fatalf("OLE2 file routed to %v (ok=%v), want office2smith", d, ok)
	}
	if conf != hashid.Likely {
		t.Errorf("confidence = %s, want likely (bare OLE2 magic; not confirmed as encrypted Office)", conf)
	}
}

func TestSniffOfficeWithEncryptionInfoStreamIsCertain(t *testing.T) {
	head := []byte{0xD0, 0xCF, 0x11, 0xE0}
	head = append(head, make([]byte, 64)...)
	head = append(head, utf16LEBytes("EncryptionInfo")...)
	p := writeTemp(t, "Encrypted.docx.cfb", head)

	d, ev, conf, ok := sniffContainer(p)
	if !ok || d.name != "office2smith" {
		t.Fatalf("routed to %v (ok=%v), want office2smith", d, ok)
	}
	if conf != hashid.Certain {
		t.Errorf("confidence = %s, want certain (EncryptionInfo stream name found)", conf)
	}
	if !strings.Contains(string(ev), "EncryptionInfo") {
		t.Errorf("evidence = %q, want it to mention EncryptionInfo", ev)
	}
}

// TestSniffPwsafeBareTagIsLikelyNotCertain is a regression test for T16/M11:
// pwsafe2smith used to assert Certain for a bare "PWS3" 4-byte tag even
// though its own evidence string admits "no secondary structural check
// beyond the signature itself" — a contradiction between the confidence word
// and the honesty of the evidence text next to it.
func TestSniffPwsafeBareTagIsLikelyNotCertain(t *testing.T) {
	p := writeTemp(t, "vault.psafe3", append([]byte("PWS3"), make([]byte, 64)...))
	d, ev, conf, ok := sniffContainer(p)
	if !ok || d.name != "pwsafe2smith" {
		t.Fatalf("routed to %v (ok=%v), want pwsafe2smith", d, ok)
	}
	if conf != hashid.Likely {
		t.Errorf("confidence = %s, want likely (bare 4-byte tag, no secondary check)", conf)
	}
	if !strings.Contains(string(ev), "no secondary structural check") {
		t.Errorf("evidence = %q, want it to keep admitting the lack of a secondary check", ev)
	}
}

// TestSniffHccapxBareTagIsLikelyNotCertain is a regression test for T16/M11:
// hccapx2smith used to assert Certain for a bare "HCPX" 4-byte tag with no
// structural check of the record that follows it.
func TestSniffHccapxBareTagIsLikelyNotCertain(t *testing.T) {
	p := writeTemp(t, "capture.hccapx", append([]byte("HCPX"), make([]byte, 64)...))
	d, _, conf, ok := sniffContainer(p)
	if !ok || d.name != "hccapx2smith" {
		t.Fatalf("routed to %v (ok=%v), want hccapx2smith", d, ok)
	}
	if conf != hashid.Likely {
		t.Errorf("confidence = %s, want likely (bare 4-byte tag, no secondary check)", conf)
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

// TestIdentifyStillReadsAHashFileAsHashesNotAsAContainer is the integration
// check finding 5 asked for: TestSniffRejectsPlainText only proves
// sniffContainer itself declines a hash file. This drives the real
// runIdentify entry point end to end and asserts the rendered output is hash
// identification (an MD5/NTLM candidate table), not container-routing text —
// so a future reordering of the sniff-vs-read branch in runIdentify would
// fail a test instead of only being caught by inspection.
func TestIdentifyStillReadsAHashFileAsHashesNotAsAContainer(t *testing.T) {
	p := writeTemp(t, "hashes.txt", []byte(
		"5f4dcc3b5aa765d61d8327deb882cf99\n"+
			"098f6bcd4621d373cade4e832627b4f6\n"))

	out := captureStdout(t, func() error {
		return runIdentify([]string{p})
	})

	if strings.Contains(out, "This is a container") {
		t.Errorf("a two-hash text file was routed as a container:\n%s", out)
	}
	if !strings.Contains(out, "MD5") {
		t.Errorf("expected MD5 hash identification in output, got:\n%s", out)
	}
}

// TestIdentifyDashFRoutesAContainerThroughTheSniffer covers finding 4:
// identify.go's own -i help text advertises that -i (and -f) accept a file
// path, so a container passed that way must be sniffed exactly like a bare
// positional argument, not handed to readInputLines as a line-oriented hash
// file.
func TestIdentifyDashFRoutesAContainerThroughTheSniffer(t *testing.T) {
	head := append([]byte("PK\x03\x04"), make([]byte, 64)...)
	p := writeTemp(t, "archive.zip", head)

	out := captureStdout(t, func() error {
		return runIdentify([]string{"-f", p})
	})
	if !strings.Contains(out, "zip2smith") {
		t.Errorf("identify -f <zip> did not route through the sniffer:\n%s", out)
	}

	out = captureStdout(t, func() error {
		return runIdentify([]string{"-i", p})
	})
	if !strings.Contains(out, "zip2smith") {
		t.Errorf("identify -i <zip> did not route through the sniffer:\n%s", out)
	}
}

// TestIdentifyJSONAgainstContainerIsRefused is the regression test for I2:
// identify.go's container-sniff branch used to return before the --json
// branch below it, so "identify --json <container>" printed
// renderContainerIdentification's human text on stdout with no error — a
// consumer parsing hashsmith.identify/1 got unparseable output and no
// signal that anything went wrong. The combination is now refused outright,
// the same precedent runIdentifyBatch already sets for --summary --json.
func TestIdentifyJSONAgainstContainerIsRefused(t *testing.T) {
	head := append([]byte("PK\x03\x04"), make([]byte, 64)...)
	p := writeTemp(t, "archive.zip", head)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runIdentify([]string{"--json", "-f", p})
	w.Close()
	os.Stdout = old
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := r.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	out := sb.String()

	if err == nil {
		t.Fatalf("identify --json <container> succeeded; want a refusal error. stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "container") || !strings.Contains(err.Error(), "json") && !strings.Contains(err.Error(), "JSON") {
		t.Errorf("error = %q, want it to name both --json and the container restriction", err.Error())
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("identify --json <container> wrote to stdout (want nothing, error only): %q", out)
	}
}
