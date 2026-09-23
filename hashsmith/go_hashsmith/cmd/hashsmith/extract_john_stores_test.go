package main

import (
	"bytes"
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

// Every extractor below is tested against a container REBUILT FROM THE RECORD
// John's own format test carries, rather than against a fixture written by
// hand from the same understanding the extractor was written with.
//
// That matters because a hand-written fixture only proves the parser agrees
// with its author. Here the bytes come from a real file that John cracked with
// a known password, so a wrong offset shows up as either a record that does
// not match John's or one that no longer cracks — and the test asserts both.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in a test vector: %v", err)
	}
	return b
}

// writeFixture puts bytes in a temp file and returns the path.
func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return p
}

// mustCrack asserts a record is answered by the right password and refused by
// a wrong one. The second half is the half that catches a verifier reading a
// prefix.
func mustCrack(t *testing.T, typ, record, password string) {
	t.Helper()
	ok, err := verifyCandidate(password, record, typ, "", "")
	if err != nil {
		t.Fatalf("%s: verifying the extracted record: %v", typ, err)
	}
	if !ok {
		t.Fatalf("%s: the extracted record does not crack with %q", typ, password)
	}
	if bad, err := verifyCandidate(password+"!", record, typ, "", ""); err != nil || bad {
		t.Fatalf("%s: the extracted record accepted a wrong password (%v, %v)", typ, bad, err)
	}
}

func TestExtractKeystoreRoundTrip(t *testing.T) {
	record, password := johnVector(t, "keystore $keystore$")
	f := strings.Split(strings.TrimPrefix(record, "$keystore$"), "$")
	// The file is exactly the store body followed by its digest.
	file := append(mustHex(t, f[2]), mustHex(t, f[3])...)

	got, err := extractKeystoreRecords(writeFixture(t, "debug.keystore", file))
	if err != nil {
		t.Fatalf("extractKeystoreRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("keystore2smith did not reproduce John's record.\n got: %.80s...\nwant: %.80s...", got[0], record)
	}
	mustCrack(t, "jks-keystore", got[0], password)
}

func TestExtractBKSRoundTrip(t *testing.T) {
	record, password := johnVector(t, "BKS $bks$")
	f := strings.Split(strings.TrimPrefix(record, "$bks$"), "$")
	version, _ := strconv.Atoi(f[1])
	iterations, _ := strconv.Atoi(f[3])
	salt := mustHex(t, f[5])

	var file bytes.Buffer
	be := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		file.Write(b[:])
	}
	be(uint32(version))
	be(uint32(len(salt)))
	file.Write(salt)
	be(uint32(iterations))
	file.Write(mustHex(t, f[6]))
	file.Write(mustHex(t, f[7]))

	got, err := extractBKSRecords(writeFixture(t, "store.bks", file.Bytes()))
	if err != nil {
		t.Fatalf("extractBKSRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("bks2smith did not reproduce John's record.\n got: %.80s...\nwant: %.80s...", got[0], record)
	}
	mustCrack(t, "bks", got[0], password)
}

func TestExtractKeyringRoundTrip(t *testing.T) {
	record, password := johnVector(t, "keyring $keyring$")
	f := strings.Split(strings.TrimPrefix(record, "$keyring$"), "*")
	salt := mustHex(t, f[0])
	iterations, _ := strconv.Atoi(f[1])
	ct := mustHex(t, f[4])

	name := []byte("login")
	var file bytes.Buffer
	file.WriteString(gnomeKeyringMagic)
	file.Write([]byte{0, 0}) // version
	file.WriteByte(0)        // crypto: AES
	file.WriteByte(0)        // hash: MD5
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(name)))
	file.Write(b4[:])
	file.Write(name)
	file.Write(make([]byte, 8)) // ctime
	file.Write(make([]byte, 8)) // mtime
	file.Write(make([]byte, 4)) // flags
	file.Write(make([]byte, 4)) // lock timeout
	binary.BigEndian.PutUint32(b4[:], uint32(iterations))
	file.Write(b4[:])
	file.Write(salt)
	file.Write(make([]byte, 16)) // reserved
	file.Write(make([]byte, 8))  // item count
	file.Write(ct)

	got, err := extractKeyringRecords(writeFixture(t, "login.keyring", file.Bytes()))
	if err != nil {
		t.Fatalf("extractKeyringRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("keyring2smith did not reproduce John's record.\n got: %s\nwant: %s", got[0], record)
	}
	mustCrack(t, "keyring", got[0], password)
}

func TestExtractKWalletRoundTrip(t *testing.T) {
	record, password := johnVector(t, "kwallet $kwallet$")
	f := strings.Split(strings.TrimPrefix(record, "$kwallet$"), "$")
	encrypted := mustHex(t, f[1])

	var file bytes.Buffer
	file.WriteString(kwalletMagic)
	file.Write([]byte{0, 0, 0, 0}) // major, minor, Blowfish-ECB, SHA-1
	file.Write([]byte{0, 0, 0, 1}) // one folder
	file.Write(make([]byte, 16))   // its name hash
	file.Write([]byte{0, 0, 0, 2}) // holding two entries
	file.Write(make([]byte, 32))   // their name hashes
	file.Write(encrypted)

	got, err := extractKWalletRecords(writeFixture(t, "kdewallet.kwl", file.Bytes()))
	if err != nil {
		t.Fatalf("extractKWalletRecords: %v", err)
	}
	// John's own record carries the whole encrypted region where this
	// carries the leading sixty-five bytes the check reads, so the two are
	// not byte-identical. What must hold is that the record still cracks.
	if len(got) != 1 {
		t.Fatalf("kwallet2smith returned %d records, want 1", len(got))
	}
	if !strings.HasPrefix(got[0], fmt.Sprintf("$kwallet$%d$", len(encrypted))) {
		t.Fatalf("kwallet2smith lost the encrypted region's length: %.40s", got[0])
	}
	mustCrack(t, "kwallet", got[0], password)
}

// A salted wallet is useless without its sibling .salt file, and saying so is
// better than emitting a record that cannot crack.
func TestExtractKWalletSaltedNeedsItsSibling(t *testing.T) {
	var file bytes.Buffer
	file.WriteString(kwalletMagic)
	file.Write([]byte{0, 1, 0, 2}) // minor 1, Blowfish-ECB, PBKDF2-SHA512
	file.Write([]byte{0, 0, 0, 0}) // no folders
	file.Write(make([]byte, 96))

	dir := t.TempDir()
	walletPath := filepath.Join(dir, "kdewallet.kwl")
	if err := os.WriteFile(walletPath, file.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := extractKWalletRecords(walletPath); err == nil ||
		!strings.Contains(err.Error(), "kdewallet.salt") {
		t.Fatalf("a salted wallet with no salt file should name the file it needs, got %v", err)
	}

	salt := []byte("0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, "kdewallet.salt"), salt, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := extractKWalletRecords(walletPath)
	if err != nil {
		t.Fatalf("with the salt file present: %v", err)
	}
	want := fmt.Sprintf("$kwallet$96$%s$1$16$%s$50000",
		hex.EncodeToString(file.Bytes()[len(kwalletMagic)+8:][:65]),
		hex.EncodeToString(salt))
	if got[0] != want {
		t.Fatalf("salted wallet record\n got: %s\nwant: %s", got[0], want)
	}
}

func TestExtractKnownHostsRoundTrip(t *testing.T) {
	record, hostname := johnVector(t, "known_hosts $known_hosts$")
	entry := strings.TrimPrefix(record, "$known_hosts$")

	file := "# a comment\n" +
		"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n" +
		entry + " ssh-rsa AAAAB3NzaC1yc2E=\n"

	got, err := extractKnownHostsRecords(writeFixture(t, "known_hosts", []byte(file)))
	if err != nil {
		t.Fatalf("extractKnownHostsRecords: %v", err)
	}
	// The unhashed line is already its own answer, so it must NOT be
	// emitted as something to crack.
	if len(got) != 1 || got[0] != record {
		t.Fatalf("known_hosts2smith returned %v, want just %s", got, record)
	}
	ok, err := verifyCandidate(hostname, got[0], "known-hosts", "", "")
	if err != nil || !ok {
		t.Fatalf("the extracted known_hosts record does not match %q (%v, %v)", hostname, ok, err)
	}
}

func TestExtractHtdigest(t *testing.T) {
	// MD5("bob:Restricted Area:hunter2"), computed by the dynamic
	// expression the record names, so the test states the input rather
	// than a digest copied from somewhere.
	const user, realm, password = "bob", "Restricted Area", "hunter2"

	file := "alice:Other:0123456789abcdef0123456789abcdef\n" +
		"# comment\n" +
		"malformed line\n" +
		user + ":" + realm + ":" + md5HexOf(user+":"+realm+":"+password) + "\n"

	got, gerr := extractHtdigestRecords(writeFixture(t, ".htdigest", []byte(file)))
	if gerr != nil {
		t.Fatalf("extractHtdigestRecords: %v", gerr)
	}
	if len(got) != 2 {
		t.Fatalf("htdigest2smith returned %d records, want 2", len(got))
	}
	wantSalt := hex.EncodeToString([]byte(user + ":" + realm + ":"))
	if !strings.HasSuffix(got[1], "$HEX$"+wantSalt) {
		t.Fatalf("the realm did not reach the record as hex: %s", got[1])
	}
	mustCrack(t, "dynamic", got[1], password)
}

func TestExtractPuttyRoundTrip(t *testing.T) {
	record, password := johnVector(t, "PuTTY $putty$")
	f := strings.Split(strings.TrimPrefix(record, "$putty$"), "*")
	mac, public, private := f[4], mustHex(t, f[6]), mustHex(t, f[8])
	algorithm, encryption, comment := f[9], f[10], f[11]

	lines := func(b []byte) (int, string) {
		enc := base64.StdEncoding.EncodeToString(b)
		var out strings.Builder
		n := 0
		for len(enc) > 64 {
			out.WriteString(enc[:64] + "\n")
			enc = enc[64:]
			n++
		}
		out.WriteString(enc + "\n")
		return n + 1, out.String()
	}
	pubN, pubText := lines(public)
	privN, privText := lines(private)

	file := "PuTTY-User-Key-File-2: " + algorithm + "\n" +
		"Encryption: " + encryption + "\n" +
		"Comment: " + comment + "\n" +
		"Public-Lines: " + strconv.Itoa(pubN) + "\n" + pubText +
		"Private-Lines: " + strconv.Itoa(privN) + "\n" + privText +
		"Private-MAC: " + mac + "\n"

	got, err := extractPuttyRecords(writeFixture(t, "key.ppk", []byte(file)))
	if err != nil {
		t.Fatalf("extractPuttyRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("putty2smith did not reproduce John's record.\n got: %.100s...\nwant: %.100s...", got[0], record)
	}
	mustCrack(t, "putty", got[0], password)
}

// A version 3 key is refused by name rather than misread as a version 2 one,
// because its Argon2 derivation is a different problem and a record claiming
// otherwise would be answered wrongly.
func TestExtractPuttyRefusesVersion3ByName(t *testing.T) {
	file := "PuTTY-User-Key-File-3: ssh-ed25519\n" +
		"Encryption: aes256-cbc\n" +
		"Comment: k\n" +
		"Key-Derivation: Argon2id\n" +
		"Public-Lines: 1\nAAAA\n" +
		"Private-Lines: 1\nAAAA\n" +
		"Private-MAC: " + strings.Repeat("ab", 20) + "\n"
	_, err := extractPuttyRecords(writeFixture(t, "v3.ppk", []byte(file)))
	if err == nil || !strings.Contains(err.Error(), "Argon2") {
		t.Fatalf("a PPK version 3 key should be refused by name, got %v", err)
	}
}
