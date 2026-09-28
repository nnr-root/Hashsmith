package smith

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These four records were produced from files `openssl enc` actually wrote
// (OpenSSL 3.6.3), and two of them could not be answered before:
//
//   - a cipher field of 0 was refused outright, because the field was read as
//     a key length rather than as John's cipher index, where 0 is AES-256 and
//     1 is AES-128. openssl2john's DEFAULT run writes 0, so records straight
//     out of John's own converter were the ones being refused.
//
//   - the non-inlined form, where the sample carries the block before the last
//     one, was decrypted as if the derived IV chained into the whole sample.
//     CBC recovers from a wrong IV after one block, so the padding still
//     checked out and only the printability test failed — the right password
//     was rejected with no sign of why.
//
// The self-test vector that existed was AES-128 AND inlined, which is the one
// combination both defects leave alone.
func TestOpenSSLEncRealFiles(t *testing.T) {
	cases := []struct{ name, record string }{
		{
			"AES-256, MD5, two blocks",
			"$openssl$0$0$8$0b2aa18c18a4afb2$9e15447c9274c9b9513d1a7726945a0e807dd12163dbce7f2c451ff3d215a241$0$48$13393c6678ffe31b2e53ddfc43a9475e9e15447c9274c9b9513d1a7726945a0e807dd12163dbce7f2c451ff3d215a241$0",
		},
		{
			"AES-128, MD5, two blocks",
			"$openssl$1$0$8$a419b4a438cee9f8$c1341a23f859b62bf76845cdd65f6cf8cd2d119d057c2edc7fe7de07dd54dd59$0$48$213582ee19a903bff581a9c0fcf4b8b0c1341a23f859b62bf76845cdd65f6cf8cd2d119d057c2edc7fe7de07dd54dd59$0",
		},
		{
			"AES-256, MD5, one block",
			"$openssl$0$0$8$9c2d4a7ae69f3443$27ae2482792f025b6ae1bce79a8a05d5$1$0",
		},
		{
			"AES-128, MD5, one block (John's own vector)",
			"$openssl$1$0$8$a1a5e529c8d92da5$8de763bf61377d365243993137ad9729$1$0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := verifyOpenSSLEnc(c.record, "password")
			if err != nil {
				t.Fatalf("verifyOpenSSLEnc: %v", err)
			}
			if !ok {
				t.Error("the right password was rejected")
			}
			for _, wrong := range []string{"Password", "password1", "passwor", ""} {
				bad, err := verifyOpenSSLEnc(c.record, wrong)
				if err != nil {
					t.Fatalf("verifyOpenSSLEnc(%q): %v", wrong, err)
				}
				if bad {
					t.Errorf("accepted the wrong password %q", wrong)
				}
			}
		})
	}
}

// There is no cipher index 2 or 3: John implements AES-256 and AES-128 and
// nothing else, so a record naming anything else is a record this tool cannot
// honestly read.
func TestOpenSSLEncRejectsInventedCiphers(t *testing.T) {
	for _, cipher := range []string{"2", "3", "9"} {
		record := "$openssl$" + cipher + "$0$8$a1a5e529c8d92da5$8de763bf61377d365243993137ad9729$1$0"
		if _, err := verifyOpenSSLEnc(record, "password"); err == nil {
			t.Errorf("cipher %q should be refused", cipher)
		}
	}
}

// The whole loop, when openssl is on the machine: encrypt a file, extract the
// records, and check that exactly one of the six answers and that it answers
// only the right password.
func TestExtractOpenSSLEncRoundTrip(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed here, so no file can be built")
	}
	const password = "correct horse battery staple"
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain,
		[]byte("The quick brown fox jumps over the lazy dog, repeatedly.\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"aes-256-cbc/md5", []string{"enc", "-aes-256-cbc", "-md", "md5"}},
		{"aes-128-cbc/sha256", []string{"enc", "-aes-128-cbc", "-md", "sha256"}},
		{"aes-256-cbc/sha1 base64", []string{"enc", "-aes-256-cbc", "-md", "sha1", "-a"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(dir, strings.NewReplacer("/", "_", " ", "_").Replace(c.name)+".enc")
			args := append(append([]string{}, c.args...),
				"-in", plain, "-out", out, "-pass", "pass:"+password)
			if err := exec.Command(bin, args...).Run(); err != nil {
				t.Skipf("this openssl refused %v: %v", c.args, err)
			}
			records, err := extractOpenSSLEncRecords(out)
			if err != nil {
				t.Fatalf("extractOpenSSLEncRecords: %v", err)
			}
			if len(records) != len(opensslEncCombinations) {
				t.Fatalf("got %d records, want one per combination", len(records))
			}
			matched := 0
			for _, r := range records {
				ok, err := verifyOpenSSLEnc(r, password)
				if err != nil {
					t.Fatalf("verifyOpenSSLEnc: %v", err)
				}
				if ok {
					matched++
					if bad, _ := verifyOpenSSLEnc(r, password+"!"); bad {
						t.Errorf("the matching record also accepted a wrong password")
					}
				}
			}
			if matched != 1 {
				t.Errorf("%d of %d records answered, want exactly 1", matched, len(records))
			}
		})
	}
}
