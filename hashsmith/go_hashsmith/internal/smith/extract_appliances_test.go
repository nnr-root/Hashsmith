package smith

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// The AEM lines below are John's own worked examples, from the header of
// aem2john.py, together with the passwords that header gives for them. They
// are the closest thing this format has to a published vector.
const (
	aemExampleNoUser  = "{SHA-256}a9d4b340cb43807b-1000-33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275"
	aemExampleSHA256  = "jsmith:{SHA-256}fe90d85cdcd7e79c-1000-ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912"
	aemExampleSHA512  = "admin:{SHA-512}fe90d85cdcd7e79c-1000-4c29a0ac964e7bbc5380797f294d15928288cbcde3d501eb8746296de8d6c06b2b5ff27b56ae174744fe69ee157614ad126c1315ee3b67c891e42753e01a3e37"
	aemPasswordNoUser = "admin"
	aemPasswordOther  = "Aa12345678!@"
)

func TestExtractAEM(t *testing.T) {
	file := "# a comment\n" +
		aemExampleNoUser + "\n" +
		aemExampleSHA256 + "\n" +
		aemExampleSHA512 + "\n" +
		"{MD5}notsupported-1000-abcd\n"

	got, err := extractAEMRecords(writeFixture(t, "aem.txt", []byte(file)))
	if err != nil {
		t.Fatalf("extractAEMRecords: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3 (the {MD5} line has no reader): %v", len(got), got)
	}
	// The record puts the ITERATION COUNT before the salt where the file
	// puts the salt first, so this is where a copy-the-fields-across reader
	// goes wrong.
	want := []string{
		"$sspr$3$1000$a9d4b340cb43807b$33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275",
		"jsmith:$sspr$3$1000$fe90d85cdcd7e79c$ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912",
		"admin:$sspr$4$1000$fe90d85cdcd7e79c$4c29a0ac964e7bbc5380797f294d15928288cbcde3d501eb8746296de8d6c06b2b5ff27b56ae174744fe69ee157614ad126c1315ee3b67c891e42753e01a3e37",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record %d\n got: %s\nwant: %s", i, got[i], want[i])
		}
	}
	// And each one has to crack with the password John's header gives.
	mustCrack(t, "sspr", got[0], aemPasswordNoUser)
	for _, i := range []int{1, 2} {
		_, record, _ := strings.Cut(got[i], ":")
		mustCrack(t, "sspr", record, aemPasswordOther)
	}
}

func TestExtractPfSense(t *testing.T) {
	const bcryptHash = "$2a$05$b96jf5l0vVZKd1cImA3foeAOMZ87EM8xgadlUKv2nFS6Y5C24GlKq"
	const md5Hash = "5f4dcc3b5aa765d61d8327deb882cf99"
	doc := `<?xml version="1.0"?><pfsense><system>` +
		`<user><name>admin</name><bcrypt-hash>` + bcryptHash + `</bcrypt-hash></user>` +
		// An upgraded account keeps both, and the OLD one is still a way in.
		`<user><name>legacy</name><bcrypt-hash>` + bcryptHash + `</bcrypt-hash>` +
		`<md5-hash>` + md5Hash + `</md5-hash></user>` +
		`<user><name>nopass</name></user>` +
		`</system></pfsense>`

	got, err := extractPfSenseRecords(writeFixture(t, "config.xml", []byte(doc)))
	if err != nil {
		t.Fatalf("extractPfSenseRecords: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3 (both of the upgraded account's): %v", len(got), got)
	}
	mustCrack(t, "bcrypt", got[0], "password")
	mustCrack(t, "md5", got[2], "password")
}

func TestExtractAPEX(t *testing.T) {
	const user, group, password = "ADMIN", "1234567890", "secret"
	// dynamic_1 is md5($p.$s), and the salt is the security group id
	// followed by the user name — two columns, in an order the file does
	// not state.
	sum := md5.Sum([]byte(password + group + user))
	line := fmt.Sprintf(" %s , %s , %s \n", user, hex.EncodeToString(sum[:]), group)

	got, err := extractAPEXRecords(writeFixture(t, "apex.csv", []byte(line+"malformed\n")))
	if err != nil {
		t.Fatalf("extractAPEXRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(got), got)
	}
	if !strings.HasSuffix(got[0], "$"+group+user) {
		t.Fatalf("the salt is not the group followed by the user: %s", got[0])
	}
	mustCrack(t, "dynamic", got[0], password)
}

func TestExtractGitea(t *testing.T) {
	const password = "hunter2"
	const iterations = 10000
	salt := []byte("salt123")
	// Gitea stores fifty bytes; the record keeps thirty-two.
	key := pbkdf2.Key([]byte(password), salt, iterations, 50, sha256.New)

	for _, sep := range []string{":", "|"} {
		t.Run("separated by "+sep, func(t *testing.T) {
			line := strings.Join([]string{
				"isaac", hex.EncodeToString(salt), hex.EncodeToString(key),
				fmt.Sprintf("pbkdf2$%d$50", iterations),
			}, sep) + "\n"

			got, err := extractGiteaRecords(writeFixture(t, "gitea.txt", []byte(line)))
			if err != nil {
				t.Fatalf("extractGiteaRecords: %v", err)
			}
			want := fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s", iterations,
				base64.StdEncoding.EncodeToString(salt),
				base64.StdEncoding.EncodeToString(key[:giteaKeyBytes]))
			if len(got) != 1 || got[0] != want {
				t.Fatalf("\n got: %v\nwant: %s", got, want)
			}
			// The database holds hex and the record holds base64. Both
			// are ASCII, so a record carrying the hex would look
			// well-formed and never crack — this is what catches that.
			mustCrack(t, "passlib-pbkdf2", got[0], password)
		})
	}
}

// A row whose algorithm column is not pbkdf2 names a scheme with no reader
// here, so it is skipped rather than turned into a pbkdf2 record.
func TestExtractGiteaSkipsOtherAlgorithms(t *testing.T) {
	line := "isaac:73616c74:" + strings.Repeat("ab", 50) + ":argon2$1$2$3\n"
	if _, err := extractGiteaRecords(writeFixture(t, "gitea.txt", []byte(line))); err == nil {
		t.Fatal("an argon2 row should not become a pbkdf2 record")
	}
}
