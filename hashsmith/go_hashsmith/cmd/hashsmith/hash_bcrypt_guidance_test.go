package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestBcryptHashErrorNamesAWorkingAction.
//
// `hashsmith hash -t bcrypt somepassword` used to fail with
//
//	bcrypt requires a salt (use --salt)
//
// and the hash subcommand has no --salt flag: following that advice produced
// "flag provided but not defined: -salt". The message told the operator to do
// something impossible, and it was wrong twice over — bcrypt draws its own
// random salt and embeds it in the record, so there is no salt to pass at all.
// What -s actually carries for bcrypt is the COST (the work factor stored as
// $2a$NN$).
//
// Asserting the new wording alone would only pin a string. This asserts the
// guidance is EXECUTABLE: it pulls the flag out of the message, runs the real
// `hash` command with it, and verifies the record that comes back — while
// confirming the flag the old message named still does not exist. A future
// rewording that names an unusable flag fails here.
func TestBcryptHashErrorNamesAWorkingAction(t *testing.T) {
	_, err := hashText("somepassword", "bcrypt", "", "prefix")
	if err == nil {
		t.Fatal("bcrypt with no cost must still be an error")
	}
	msg := err.Error()

	// The flag the old message named is not a flag. Prove it rather than
	// trusting the source: this is the exact check the old message failed.
	if runHash([]string{"-t", "bcrypt", "--salt", "10", "somepassword"}) == nil {
		t.Fatal("--salt now parses; this test's premise needs revisiting")
	}
	if strings.Contains(msg, "--salt") {
		t.Fatalf("error names --salt, which the hash subcommand rejects as "+
			"\"flag provided but not defined\": %s", msg)
	}

	if !strings.Contains(msg, "-s") {
		t.Fatalf("error must name -s, the flag that actually drives bcrypt hashing: %s", msg)
	}
	// It must also say what -s carries, or "-s" alone reads as the salt the
	// old message wrongly asked for.
	if !strings.Contains(strings.ToLower(msg), "cost") {
		t.Errorf("error must say -s carries bcrypt's cost, not a salt: %s", msg)
	}

	// The message carries a worked example in backticks. Every flag the prose
	// names must appear in it, so the message cannot mention a flag it never
	// demonstrates...
	example := regexp.MustCompile("`([^`]+)`").FindStringSubmatch(msg)
	if example == nil {
		t.Fatalf("error must show a runnable example command in backticks: %s", msg)
	}
	fields := strings.Fields(example[1])
	if len(fields) < 2 || fields[0] != "hashsmith" || fields[1] != "hash" {
		t.Fatalf("the example must be a `hashsmith hash ...` command line: %q", example[1])
	}
	inExample := map[string]bool{}
	for _, f := range fields {
		inExample[f] = true
	}
	flagRE := regexp.MustCompile(`-{1,2}[a-zA-Z][-a-zA-Z0-9]*`)
	for _, flag := range flagRE.FindAllString(msg, -1) {
		if !inExample[flag] {
			t.Errorf("error names %q but never shows it in its example command, so there is "+
				"nothing proving it works: %s", flag, msg)
		}
	}

	// ...and running that example verbatim must produce a usable bcrypt record
	// at the cost it asks for. This is the check the old message could not have
	// passed: `hashsmith hash -t bcrypt --salt ... ` does not parse.
	out := filepath.Join(t.TempDir(), "bcrypt.txt")
	args := append([]string{}, fields[2:]...)
	for i, a := range args {
		if a == "<password>" {
			args[i] = "somepassword"
		}
	}
	args = append(args, "-o", out)
	if err := runHash(args); err != nil {
		t.Fatalf("the example the error message gives must run; `%s` failed: %v", example[1], err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(raw))
	if err := bcrypt.CompareHashAndPassword([]byte(got), []byte("somepassword")); err != nil {
		t.Fatalf("%q is not a bcrypt record for the input: %v", got, err)
	}
	if cost, err := bcrypt.Cost([]byte(got)); err != nil || cost != 10 {
		t.Fatalf("-s 10 must set bcrypt cost 10; got cost=%d err=%v", cost, err)
	}

	// The non-integer branch has to name the same real mechanism, since an
	// operator who read "salt" and typed a salt lands here.
	_, err = hashText("somepassword", "bcrypt", "somesalt", "prefix")
	if err == nil {
		t.Fatal("a non-integer cost must be an error")
	}
	if !strings.Contains(err.Error(), "-s") || !strings.Contains(strings.ToLower(err.Error()), "cost") {
		t.Errorf("the non-integer error must also point at -s and say it is the cost: %v", err)
	}
}
