package main

// `hashsmith selftest` — run every known-answer vector compiled into the binary.
//
// This answers a question a version number cannot: is the copy of Hashsmith on
// *this* machine, built by *this* toolchain, still computing the right answers?
// A miscompilation, a bad optimisation, an incorrect CPU-feature path or a
// corrupted download all show up here and nowhere else.
//
// Each vector records where its expected value came from, because that changes
// what a pass is worth:
//
//	published    — a value from the algorithm's specification or reference suite
//	crosschecked — computed independently (Python's hashlib, OpenSSL) and pinned
//	regression   — produced by Hashsmith itself; catches drift, not original error
//
// A regression vector cannot tell you an implementation was right to begin
// with, so the summary reports the three classes separately rather than
// flattening them into one reassuring number.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
)

type vectorSource int

const (
	srcPublished vectorSource = iota
	srcCrosschecked
	srcRegression
)

func (s vectorSource) String() string {
	switch s {
	case srcPublished:
		return "published"
	case srcCrosschecked:
		return "cross-checked"
	default:
		return "regression"
	}
}

type selfTestVector struct {
	typ      string
	password string
	salt     string
	target   string
	source   vectorSource
}

// slowSelfTestTypeSeed identifies memory-hard and high-iteration KDFs. They are
// correct, but running them all would dominate the runtime, so they are opt-in:
// a quick check people actually run beats a thorough one they skip.
func slowSelfTestTypeSeed() map[string]bool {
	return map[string]bool{
		"1password": true, "ansible": true, "bitcoin": true, "bitlocker": true,
		"android-backup": true, "encfs": true,
		"bitwarden": true, "blockchain": true, "dcc2": true, "electrum": true,
		"itunes": true, "keepass": true, "oracle12c": true, "pdf-r6": true,
		"solarwinds": true, "argon2": true, "scrypt": true, "bcrypt": true,
		"aix": true, "grub2": true, "passlib-pbkdf2": true, "werkzeug": true,
		"krb5pa": true, "krb5tgs": true, "veracrypt": true, "truecrypt": true,
		"truecrypt-ripemd160": true, "truecrypt-sha512": true, "truecrypt-whirlpool": true,
		"veracrypt-ripemd160": true, "veracrypt-sha512": true, "veracrypt-whirlpool": true,
		"veracrypt-sha256":            true,
		"truecrypt-ripemd160-xts1024": true, "truecrypt-ripemd160-xts1536": true,
		"truecrypt-sha512-xts1024": true, "truecrypt-sha512-xts1536": true,
		"truecrypt-whirlpool-xts1024": true, "truecrypt-whirlpool-xts1536": true,
		"truecrypt-ripemd160-boot-xts512": true, "truecrypt-ripemd160-boot-xts1024": true,
		"truecrypt-ripemd160-boot-xts1536": true,
		"veracrypt-ripemd160-xts1024":      true, "veracrypt-ripemd160-xts1536": true,
		"veracrypt-sha512-xts1024": true, "veracrypt-sha512-xts1536": true,
		"veracrypt-whirlpool-xts1024": true, "veracrypt-whirlpool-xts1536": true,
		"veracrypt-ripemd160-boot-xts512": true, "veracrypt-ripemd160-boot-xts1024": true,
		"veracrypt-ripemd160-boot-xts1536": true,
		"veracrypt-sha256-xts1024":         true, "veracrypt-sha256-xts1536": true,
		"veracrypt-sha256-boot-xts512": true, "veracrypt-sha256-boot-xts1024": true,
		"veracrypt-sha256-boot-xts1536": true,
		"veracrypt-streebog512":         true, "veracrypt-streebog512-xts1024": true,
		"veracrypt-streebog512-xts1536":     true,
		"veracrypt-streebog512-boot-xts512": true, "veracrypt-streebog512-boot-xts1024": true,
		"veracrypt-streebog512-boot-xts1536": true,
		"macos":                              true, "atlassian": true, "aspnet-identity": true, "mysql8": true,
		"django": true, "cisco4": true, "luks": true, "ldap-pbkdf2": true,
		"luks-sha1-aes": true, "luks-sha1-serpent": true, "luks-sha1-twofish": true,
		"luks-sha256-aes": true, "luks-sha256-serpent": true, "luks-sha256-twofish": true,
		"luks-sha512-aes": true, "luks-sha512-serpent": true, "luks-sha512-twofish": true,
		"luks-ripemd160-aes": true, "luks-ripemd160-serpent": true, "luks-ripemd160-twofish": true,
		"ethereum": true, "office": true, "7z": true, "rar4": true, "pdf": true,
		"ssh": true, "gpg": true, "ike": true,
		"bcrypt-md5": true, "bcrypt-sha1": true, "bcrypt-sha256": true, "pfx": true,
		"pwsafe":   true,
		"lastpass": true, "netiq-pbkdf2": true, "sspr": true,
		"wordpress-bcrypt":   true,
		"apple-secure-notes": true, "office2016-sheet": true,
		"bcrypt-sha512": true, "passlib-bcrypt-sha256": true,
		"knx-ip-secure":     true,
		"virtualbox-aes128": true, "virtualbox-aes256": true, "exodus": true,
	}
}

func runSelfTest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only := fs.String("t", "", "test a single hash type")
	verbose := fs.Bool("v", false, "list every vector, not just failures")
	showGaps := fs.Bool("gaps", false, "list registry formats that have no vector")
	withSlow := fs.Bool("slow", false, "include high-iteration KDFs (much slower)")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	vectors := universalHashRegistry.vectors
	if *only != "" {
		want := canonicalHashType(*only)
		var picked []selfTestVector
		for _, v := range vectors {
			if canonicalHashType(v.typ) == want {
				picked = append(picked, v)
			}
		}
		if len(picked) == 0 {
			return fmt.Errorf("no self-test vector for type %q", *only)
		}
		vectors = picked
	}

	var failures []string
	bySource := map[vectorSource]int{}
	skipped := 0

	for _, v := range vectors {
		if universalHashRegistry.isSlow(v.typ) && !*withSlow && *only == "" {
			skipped++
			continue
		}
		ok, err := verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("%-30s error: %v", v.typ, err))
			continue
		case !ok:
			failures = append(failures, fmt.Sprintf("%-30s did not match its known answer", v.typ))
			continue
		}
		// A verifier that accepted everything would pass the check above, so
		// each vector is also required to reject a wrong password.
		if bad, _ := verifyCandidate(wrongPassword(v.password), v.target, v.typ, v.salt, "prefix"); bad {
			failures = append(failures, fmt.Sprintf("%-30s accepted a wrong password", v.typ))
			continue
		}
		bySource[v.source]++
		if *verbose {
			fmt.Printf("  %-30s ok   %s\n", v.typ, v.source)
		}
	}

	ran := len(vectors) - skipped
	passed := ran - len(failures)
	fmt.Println()
	accentPrintln(fmt.Sprintf("Self-test: %d/%d vectors passed", passed, ran))
	fmt.Printf("  %-14s %d\n", "published", bySource[srcPublished])
	fmt.Printf("  %-14s %d\n", "cross-checked", bySource[srcCrosschecked])
	fmt.Printf("  %-14s %d\n", "regression", bySource[srcRegression])
	if skipped > 0 {
		fmt.Printf("  %-14s %d (run with -slow to include)\n", "skipped", skipped)
	}

	covered, uncovered := selfTestCoverage()
	fmt.Printf("\n  %d of %d registry formats carry a vector; %d do not.\n",
		len(covered), len(covered)+len(uncovered), len(uncovered))
	if *showGaps && len(uncovered) > 0 {
		fmt.Println("\nTypes without a self-test vector:")
		for _, name := range uncovered {
			fmt.Printf("  %s\n", name)
		}
	} else if len(uncovered) > 0 {
		fmt.Println("  Run with -gaps to list them.")
	}

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "\nFAILED:")
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		return fmt.Errorf("%d self-test vector(s) failed", len(failures))
	}
	fmt.Println()
	return nil
}

// wrongPassword mutates the first byte rather than appending to the end.
//
// Appending would not work: DES crypt truncates at 8 characters, LM at 14 and
// bcrypt at 72, so a longer password with the same prefix hashes identically
// and the negative check would report a false failure. Changing the first byte
// is the one mutation every format actually sees.
func wrongPassword(password string) string {
	if password == "" {
		return "x"
	}
	first := byte('a')
	if password[0] == 'a' {
		first = 'b'
	}
	return string(first) + password[1:]
}

// selfTestCoverage derives coverage directly from the universal registry.
func selfTestCoverage() (covered, uncovered []string) {
	for name, format := range universalHashRegistry.formats {
		if len(format.vectors) > 0 {
			covered = append(covered, name)
		} else {
			uncovered = append(uncovered, name)
		}
	}
	sort.Strings(covered)
	sort.Strings(uncovered)
	return covered, uncovered
}
