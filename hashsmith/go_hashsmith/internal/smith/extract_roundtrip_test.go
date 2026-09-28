package smith

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── Extractor round trips ─────────────────────────────────────────────────────
//
// No test anywhere took a REAL container file, ran the extractor over it, and
// then cracked the record it produced with the password the file was built
// with. Every extractor test used a hand-written fixture, which checks that
// the parser reads what the test author believed the format to be — not what
// the format is.
//
// Each case here does the whole loop:
//
//	build a container with a known password
//	  -> extract a record from it
//	    -> crack that record with the password   (must be FOUND)
//	    -> crack it with a different password    (must NOT be found)
//
// The second check matters as much as the first. A verifier that accepts a
// short prefix, or that drops the authentication tag, reports a wrong password
// as correct — and a round trip that only tested the right password would pass
// happily while the extractor was useless.

// requireTool skips the test when a container-building tool is absent, which
// is the normal case in CI. A skip says so; it does not pass quietly.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed here, so this container cannot be built", name)
	}
	return p
}

// extractRecords runs an extractor over a file and returns the records.
func extractRecords(t *testing.T, bin, extractor, path string) []string {
	t.Helper()
	cmd := exec.Command(bin, "-N", extractor, "-f", path)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s -f %s failed: %v\n%s", extractor, filepath.Base(path), err, out)
	}
	var recs []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Extractors print the record twice: once behind a "Hash:" label in
		// the human summary and once bare, so that a shell pipeline can take
		// it. Strip the label and drop the duplicate, or a test comparing
		// recs[0] against a prefix is really testing the summary's wording.
		if i := strings.Index(line, ":"); i > 0 && i < 24 && !strings.HasPrefix(line, "$") {
			if rest := strings.TrimSpace(line[i+1:]); strings.HasPrefix(rest, "$") {
				line = rest
			}
		}
		// A record is the line that carries the format tag; the rest is banner
		// and commentary.
		if strings.HasPrefix(line, "$") || strings.Contains(line, "$") && len(line) > 20 {
			if !seen[line] {
				seen[line] = true
				recs = append(recs, line)
			}
		}
	}
	if len(recs) == 0 {
		t.Fatalf("%s produced no record for %s:\n%s", extractor, filepath.Base(path), out)
	}
	return recs
}

// crackRecord reports whether the record cracks with candidate.
func crackRecord(t *testing.T, bin, record, candidate string) bool {
	t.Helper()
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte(candidate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "rec.txt")
	if err := os.WriteFile(rec, []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-N", "crack", rec, "-w", wl, "--no-pot")
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+dir)
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "Found:") ||
		strings.Contains(string(out), ":"+candidate)
}

// assertRoundTrip runs the whole loop for one container.
func assertRoundTrip(t *testing.T, bin, extractor, path, password string) {
	t.Helper()
	records := extractRecords(t, bin, extractor, path)
	t.Logf("%s produced %d record(s); first is %.70s", extractor, len(records), records[0])

	var cracked bool
	for _, r := range records {
		if crackRecord(t, bin, r, password) {
			cracked = true
			break
		}
	}
	if !cracked {
		t.Errorf("%s: no record cracked with the password the container was built with (%q)",
			extractor, password)
	}

	// A wrong password must be rejected by EVERY record. One that accepts it
	// is worse than one that fails outright: it reports a wrong answer.
	const wrong = "definitely-not-the-password-9137"
	for _, r := range records {
		if crackRecord(t, bin, r, wrong) {
			t.Errorf("%s: a record accepted a wrong password — this extractor reports false positives\n  %.90s",
				extractor, r)
		}
	}
}

func TestZipCryptoRoundTrip(t *testing.T) {
	zipBin := requireTool(t, "zip")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("round trip payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "legacy.zip")
	const password = "correct horse"
	cmd := exec.Command(zipBin, "-j", "-P", password, archive, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("zip could not build a ZipCrypto archive: %v\n%s", err, out)
	}

	// The record must be the CRC-verified form. ZipCrypto's encryption header
	// offers ONE check byte, so a record carrying only that accepts one wrong
	// password in 256 — and this very test used to fail intermittently
	// because a fresh archive plus one fixed wrong password lands on that
	// 1-in-256 every so often.
	//
	// Info-ZIP's zip, which built this archive, sets bit 3 of the entry's
	// flags, so its local header holds zeroes where the CRC and sizes belong.
	// Reaching the central directory for them is what makes the exact check
	// possible HERE rather than only for archives 7-Zip wrote, so asserting
	// the shape is asserting that the common case is the checked one.
	recs := extractRecords(t, bin, "zip2smith", archive)
	if n := strings.Count(recs[0], "$"); n < 6 {
		t.Errorf("zip2smith produced a check-byte-only ZipCrypto record; the archive's CRC was "+
			"available and would have made it exact:\n%s", recs[0])
	}

	assertRoundTrip(t, bin, "zip2smith", archive, password)
}

// TestZipCryptoRejectsWrongPasswordsInBulk is the reason the record grew.
//
// One check byte accepts one wrong password in 256. Over a rockyou-sized run
// that is thousands of reported passwords that do not open the archive, with
// nothing to tell them apart from the real one, and a round trip over a single
// wrong password cannot see it — it either gets unlucky and fails for reasons
// that look like a bug, or gets lucky and says nothing.
//
// Several hundred wrong passwords make the difference unmissable: the check
// byte alone would accept one or two of them, and the CRC accepts none.
func TestZipCryptoRejectsWrongPasswordsInBulk(t *testing.T) {
	zipBin := requireTool(t, "zip")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("bulk payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "bulk.zip")
	const password = "correct horse"
	if out, err := exec.Command(zipBin, "-j", "-P", password, archive, payload).CombinedOutput(); err != nil {
		t.Skipf("zip could not build a ZipCrypto archive: %v\n%s", err, out)
	}
	record := extractRecords(t, bin, "zip2smith", archive)[0]

	const tries = 2000
	accepted := 0
	for i := 0; i < tries; i++ {
		ok, err := verifyCandidate(fmt.Sprintf("wrongpw-%d", i), record, "zipcrypto", "", "")
		if err != nil {
			t.Fatalf("verifier errored on a wrong password: %v", err)
		}
		if ok {
			accepted++
		}
	}
	if accepted > 0 {
		t.Errorf("%d of %d wrong passwords were accepted; with only the one-byte check that is "+
			"the expected ~%d, so the CRC is not being checked", accepted, tries, tries/256)
	}

	// And the right password must still be found, so a verifier that rejects
	// everything cannot pass the test above.
	ok, err := verifyCandidate(password, record, "zipcrypto", "", "")
	if err != nil || !ok {
		t.Errorf("the correct password was rejected (ok=%v err=%v)", ok, err)
	}
}

func TestZipAESRoundTrip(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("aes payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "aes.zip")
	const password = "correct horse"
	cmd := exec.Command(sevenZip, "a", "-tzip", "-mem=AES256", "-p"+password, archive, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("7z could not build a WinZip AES archive: %v\n%s", err, out)
	}

	// The record must be the AUTHENTICATED form. The extractor used to emit
	// $zipaes256$ with only the two-byte password verifier, which cracks this
	// test's archive perfectly well and accepts one wrong password in 65,536
	// on a real run. A round trip over a single known password cannot tell the
	// two apart, so the shape is asserted separately from the behaviour.
	recs := extractRecords(t, bin, "zip2smith", archive)
	if !strings.HasPrefix(recs[0], "$zip2$") {
		t.Errorf("zip2smith produced a verifier-only record for an archive whose size is known; "+
			"the authentication code was available and would have made it exact:\n%s", recs[0])
	}

	assertRoundTrip(t, bin, "zip2smith", archive, password)
}

// TestWinZipRecordIsHashcatCompatible checks the claim the extractor's own
// label makes: that its $zip2$ record is hashcat's, not merely shaped like it.
//
// As with 7-Zip, Hashsmith cracking its own record proves only that its
// extractor and its verifier agree, which they would even if both were wrong
// about the format. Running hashcat over the same bytes is the only check that
// reaches outside that agreement.
func TestWinZipRecordIsHashcatCompatible(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	hashcat := requireTool(t, "hashcat")
	if testing.Short() {
		t.Skip("running hashcat takes tens of seconds")
	}
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("aes payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "hc-aes.zip")
	const password = "correct horse"
	if out, err := exec.Command(sevenZip, "a", "-tzip", "-mem=AES256",
		"-p"+password, archive, payload).CombinedOutput(); err != nil {
		t.Skipf("7z could not build a WinZip AES archive: %v\n%s", err, out)
	}

	recs := extractRecords(t, bin, "zip2smith", archive)
	hashFile := filepath.Join(dir, "wz.hash")
	if err := os.WriteFile(hashFile, []byte(recs[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlist, []byte("nope\n"+password+"\nalso-nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd2 := exec.Command(hashcat, "-m", "13600", "-a", "0",
		hashFile, wordlist, "--potfile-disable", "--quiet", "--self-test-disable")
	cmd2.Stdin = strings.NewReader("")
	cmd2.Env = append(os.Environ(), "HOME="+dir)
	out, _ := cmd2.CombinedOutput()
	if !strings.Contains(string(out), ":"+password) {
		t.Errorf("hashcat did not crack the record Hashsmith calls hashcat -m 13600 compatible:\n%s\n%s",
			recs[0], out)
	}
}

// 7-Zip round trip, over every coder chain 7z writes for a password.
//
// This replaces a test that pinned a refusal. The extractor could read the AES
// parameters but not the CRC or the unpacked size, so it had nothing to check
// a password against; rather than emit a record that could never crack, it
// refused, and the refusal was asserted so the gap could not be mistaken for a
// pass. The next-header parser now exists, so the gap is closed and the format
// gets the same round trip as every other container.
//
// The chains are covered deliberately, because they take different paths
// through the extractor:
//
//	-mhe=on    AES alone over the header      -> CRC record
//	-m0=Copy   AES then the identity coder    -> CRC record
//	(default)  AES then LZMA2                 -> padding record
//
// Two of those three are byte-for-byte hashcat records; TestSevenZipRecordIsHashcatCompatible
// runs hashcat itself over them where it is installed.
func TestSevenZipRoundTrip(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("seven zip payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	const password = "correct horse"

	for _, tc := range []struct {
		name    string
		args    []string
		wantCRC bool
	}{
		{"header-encrypted", []string{"-mhe=on"}, true},
		{"stored", []string{"-m0=Copy"}, true},
		{"compressed", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(dir, tc.name+".7z")
			args := append([]string{"a", "-t7z", "-p" + password}, tc.args...)
			args = append(args, archive, payload)
			if out, err := exec.Command(sevenZip, args...).CombinedOutput(); err != nil {
				t.Skipf("7z could not build an archive: %v\n%s", err, out)
			}

			recs := extractRecords(t, bin, "7z2smith", archive)
			// The type field says which check the record carries, and getting
			// it wrong is the bug this whole test exists to catch: a CRC
			// record for a compressed chain would checksum compressed bytes
			// against a plaintext CRC and never match.
			gotCRC := strings.HasPrefix(recs[0], "$7z$0$")
			if gotCRC != tc.wantCRC {
				t.Errorf("record type is wrong for a %s archive (CRC-checked=%v, want %v):\n%s",
					tc.name, gotCRC, tc.wantCRC, recs[0])
			}

			assertRoundTrip(t, bin, "7z2smith", archive, password)
		})
	}
}

// TestSevenZipRecordIsHashcatCompatible checks the claim the extractor makes
// out loud: that a CRC-checked 7-Zip record is hashcat's own, not merely
// something shaped like it.
//
// Nothing else can establish this. Hashsmith cracking its own record proves
// only that its extractor and its verifier agree, which they would even if
// both were wrong about the format. Running hashcat over the same bytes is the
// only check that reaches outside that agreement.
//
// A padding record is deliberately NOT hashcat's — it keeps a byte count where
// hashcat keeps a codec id — so this also pins that hashcat REFUSES it rather
// than loading it and silently never cracking.
func TestSevenZipRecordIsHashcatCompatible(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	hashcat := requireTool(t, "hashcat")
	if testing.Short() {
		t.Skip("running hashcat takes tens of seconds per record")
	}
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("seven zip payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	const password = "correct horse"
	wordlist := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlist, []byte("nope\n"+password+"\nalso-nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		args          []string
		wantHashcatOK bool
	}{
		{"header-encrypted", []string{"-mhe=on"}, true},
		{"compressed", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(dir, "hc-"+tc.name+".7z")
			args := append([]string{"a", "-t7z", "-p" + password}, tc.args...)
			args = append(args, archive, payload)
			if out, err := exec.Command(sevenZip, args...).CombinedOutput(); err != nil {
				t.Skipf("7z could not build an archive: %v\n%s", err, out)
			}
			recs := extractRecords(t, bin, "7z2smith", archive)
			hashFile := filepath.Join(dir, "hc-"+tc.name+".hash")
			if err := os.WriteFile(hashFile, []byte(recs[0]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(hashcat, "-m", "11600", "-a", "0",
				hashFile, wordlist, "--potfile-disable", "--quiet", "--self-test-disable")
			cmd.Stdin = strings.NewReader("")
			cmd.Env = append(os.Environ(), "HOME="+dir)
			out, _ := cmd.CombinedOutput()
			cracked := strings.Contains(string(out), ":"+password)

			if cracked != tc.wantHashcatOK {
				if tc.wantHashcatOK {
					t.Errorf("hashcat did not crack the record Hashsmith calls hashcat-compatible:\n%s\n%s",
						recs[0], out)
				} else {
					t.Errorf("hashcat cracked a padding record, so the type field no longer keeps "+
						"the two formats apart:\n%s\n%s", recs[0], out)
				}
			}
			// "No hashes loaded" is the decisive line: hashcat rejected the
			// record at parse time and never ran an attack. Which parse error
			// it reports varies with the padding length — a short one trips
			// the token count, a longer one the separator scan — so the
			// assertion is on the outcome, not on the wording.
			if !tc.wantHashcatOK && !strings.Contains(string(out), "No hashes loaded") {
				t.Errorf("hashcat neither cracked nor cleanly refused the padding record, so a user "+
					"could mistake it for an exhausted wordlist:\n%s", out)
			}
		})
	}
}

func TestSSHKeyRoundTrip(t *testing.T) {
	keygen := requireTool(t, "ssh-keygen")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	key := filepath.Join(dir, "id_rsa")
	const password = "correct horse"
	cmd := exec.Command(keygen, "-t", "rsa", "-b", "2048", "-N", password, "-f", key, "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen could not build a key: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "ssh2smith", key, password)
}

func TestPKCS12RoundTrip(t *testing.T) {
	ossl := requireTool(t, "openssl")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	key := filepath.Join(dir, "k.pem")
	crt := filepath.Join(dir, "c.pem")
	p12 := filepath.Join(dir, "bundle.p12")
	const password = "correct horse"

	gen := exec.Command(ossl, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
		"-out", crt, "-days", "1", "-nodes", "-subj", "/CN=hashsmith-test")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("openssl could not build a certificate: %v\n%s", err, out)
	}
	pack := exec.Command(ossl, "pkcs12", "-export", "-out", p12, "-inkey", key,
		"-in", crt, "-passout", "pass:"+password)
	if out, err := pack.CombinedOutput(); err != nil {
		t.Skipf("openssl could not build a PKCS#12 bundle: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "pfx2smith", p12, password)
}
