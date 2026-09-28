package smith

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// The plists here are built by macOS's OWN plutil rather than by hand, which
// is the whole point: a hand-written binary plist tests the reader against its
// author's understanding of the format, and a plutil-written one tests it
// against Apple's.

// plutilToBinary converts an XML plist to the binary form, using the system
// tool. Where that tool is absent the test says so rather than passing.
func plutilToBinary(t *testing.T, xmlText string) []byte {
	t.Helper()
	bin, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil is not on this machine, so no binary plist can be produced by its own writer")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "in.plist")
	if err := os.WriteFile(in, []byte(xmlText), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.plist")
	cmd := exec.Command(bin, "-convert", "binary1", in, "-o", out)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("plutil refused the fixture: %v\n%s", err, combined)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("bplist00")) {
		t.Fatal("plutil did not write a binary plist")
	}
	return got
}

// macShadowXML is the inner plist: the one macOS stores as a data value.
func macShadowXML(salt, entropy []byte, iterations int) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict>` +
		`<key>SALTED-SHA512-PBKDF2</key><dict>` +
		`<key>entropy</key><data>` + base64.StdEncoding.EncodeToString(entropy) + `</data>` +
		`<key>iterations</key><integer>` + fmt.Sprint(iterations) + `</integer>` +
		`<key>salt</key><data>` + base64.StdEncoding.EncodeToString(salt) + `</data>` +
		`</dict></dict></plist>`
}

// macAccountXML is the outer plist: an account file as it sits in
// /var/db/dslocal/nodes/Default/users.
func macAccountXML(shadow []byte) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict>` +
		`<key>name</key><array><string>alice</string></array>` +
		`<key>uid</key><array><string>501</string></array>` +
		`<key>ShadowHashData</key><array><data>` +
		base64.StdEncoding.EncodeToString(shadow) + `</data></array>` +
		`</dict></plist>`
}

func TestExtractMacOSRoundTrip(t *testing.T) {
	const password = "openwall"
	const iterations = 1000
	salt := []byte("0123456789abcdef0123456789abcdef")
	// macOS stores 128 bytes of entropy; the record keeps the first 64, so
	// the fixture has to carry more than the record does or the trimming
	// would go untested.
	entropy := pbkdf2.Key([]byte(password), salt, iterations, 128, sha512.New)

	want := fmt.Sprintf("$pbkdf2-hmac-sha512$%d.%s.%s",
		iterations, hex.EncodeToString(salt), hex.EncodeToString(entropy[:64]))

	shadowXML := macShadowXML(salt, entropy, iterations)
	shadowBin := plutilToBinary(t, shadowXML)
	accountBin := plutilToBinary(t, macAccountXML(shadowBin))

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"an account plist as it sits on disk", accountBin},
		// A user who could not read the account file as root, but could
		// run `defaults read`, has only the inner plist.
		{"the ShadowHashData plist alone", shadowBin},
		// And `plutil -convert xml1` gives it as text.
		{"the same, as XML", []byte(shadowXML)},
		{"the account plist, as XML", []byte(macAccountXML(shadowBin))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractMacOSRecords(writeFixture(t, "alice.plist", tc.body))
			if err != nil {
				t.Fatalf("extractMacOSRecords: %v", err)
			}
			if len(got) != 1 || got[0] != want {
				t.Fatalf("\n got: %s\nwant: %s", got[0], want)
			}
			// The record's type is named netiq-pbkdf2 in this catalogue:
			// one spelling, $pbkdf2-hmac-sha512$<iterations>.<salt>.<dk>,
			// is shared by NetIQ and by macOS, and the catalogue
			// names it after the first reader that wanted it.
			mustCrack(t, "netiq-pbkdf2", got[0], password)
		})
	}
}

// An account with no PBKDF2 entry — one that has never had a password set, or
// that carries only a legacy hash — is named rather than reported as a parse
// failure.
func TestExtractMacOSNamesAnAccountWithNoPBKDF2(t *testing.T) {
	xmlText := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<plist version="1.0"><dict><key>name</key><array><string>guest</string></array></dict></plist>`
	_, err := extractMacOSRecords(writeFixture(t, "guest.plist", []byte(xmlText)))
	if err == nil || !strings.Contains(err.Error(), "SALTED-SHA512-PBKDF2") {
		t.Fatalf("expected a named refusal, got %v", err)
	}
}

// The binary reader has to agree with plutil on the awkward parts: a
// collection with more than fourteen entries states its length separately, and
// a string with a character outside ASCII is stored as UTF-16.
func TestBinaryPlistAwkwardCases(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>`)
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&sb, `<key>k%02d</key><integer>%d</integer>`, i, i*7)
	}
	sb.WriteString(`<key>unicode</key><string>café · Ω</string>`)
	sb.WriteString(`<key>blob</key><data>` +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 300)) + `</data>`)
	sb.WriteString(`</dict></plist>`)

	v, err := plistParse(plutilToBinary(t, sb.String()))
	if err != nil {
		t.Fatalf("plistParse: %v", err)
	}
	if v.kind != plistDict || len(v.dict) != 22 {
		t.Fatalf("got %d entries, want 22", len(v.dict))
	}
	for i := 0; i < 20; i++ {
		got, ok := v.at(fmt.Sprintf("k%02d", i))
		if !ok || got.kind != plistInt || got.num != int64(i*7) {
			t.Errorf("k%02d read as %+v", i, got)
		}
	}
	if s, ok := v.at("unicode"); !ok || s.str != "café · Ω" {
		t.Errorf("the UTF-16 string read as %q", s.str)
	}
	if b, ok := v.at("blob"); !ok || len(b.data) != 300 || b.data[0] != 0xab {
		t.Errorf("the long data value read as %d bytes", len(b.data))
	}
}

// The record IS the first page, so John's own vector can be turned back into
// the file it came from and read again.
func TestExtractSTRIPRoundTrip(t *testing.T) {
	record, password := johnVector(t, "STRIP $strip$")
	page := mustHex(t, strings.TrimPrefix(record, "$strip$*"))
	if len(page) != stripPageBytes {
		t.Fatalf("John's vector carries %d bytes, want one page", len(page))
	}
	got, err := extractSTRIPRecords(writeFixture(t, "strip.db", page))
	if err != nil {
		t.Fatalf("extractSTRIPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("strip2smith did not reproduce John's record")
	}
	mustCrack(t, "strip", got[0], password)
}

func TestExtractSTRIP(t *testing.T) {
	page := make([]byte, 2048)
	for i := range page {
		page[i] = byte(i * 31)
	}
	got, err := extractSTRIPRecords(writeFixture(t, "strip.db", page))
	if err != nil {
		t.Fatalf("extractSTRIPRecords: %v", err)
	}
	want := "$strip$*" + hex.EncodeToString(page[:stripPageBytes])
	if len(got) != 1 || got[0] != want {
		t.Fatalf("strip2smith\n got: %.40s...\nwant: %.40s...", got[0], want)
	}
}

// A plaintext SQLite database has no key to find, and saying so beats handing
// back a record over it.
func TestExtractSTRIPNamesAPlaintextDatabase(t *testing.T) {
	page := make([]byte, stripPageBytes)
	copy(page, "SQLite format 3\x00")
	_, err := extractSTRIPRecords(writeFixture(t, "plain.db", page))
	if err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("expected a named refusal, got %v", err)
	}
}
