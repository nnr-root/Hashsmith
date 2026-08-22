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
	"strings"
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

// slowSelfTestTypes are the memory-hard and high-iteration KDFs. They are
// correct, but running them all would dominate the runtime, so they are opt-in:
// a quick check people actually run beats a thorough one they skip.
var slowSelfTestTypes = map[string]bool{
	"1password": true, "ansible": true, "bitcoin": true, "bitlocker": true,
	"bitwarden": true, "blockchain": true, "dcc2": true, "electrum": true,
	"itunes": true, "keepass": true, "oracle12c": true, "pdf-r6": true,
	"solarwinds": true, "argon2": true, "scrypt": true, "bcrypt": true,
	"aix": true, "grub2": true, "passlib-pbkdf2": true, "werkzeug": true,
	"krb5pa": true, "krb5tgs": true, "veracrypt": true, "truecrypt": true,
	"macos": true, "atlassian": true, "aspnet-identity": true, "mysql8": true,
	"django": true, "cisco4": true, "luks": true, "ldap-pbkdf2": true,
	"ethereum": true, "office": true, "7z": true, "rar4": true, "pdf": true,
	"ssh": true, "gpg": true, "ike": true,
	"bcrypt-md5": true, "bcrypt-sha1": true, "bcrypt-sha256": true, "pfx": true,
	"pwsafe": true,
}

func runSelfTest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only := fs.String("t", "", "test a single hash type")
	verbose := fs.Bool("v", false, "list every vector, not just failures")
	showGaps := fs.Bool("gaps", false, "list catalogue types that have no vector")
	withSlow := fs.Bool("slow", false, "include high-iteration KDFs (much slower)")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	vectors := selfTestVectors
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
		if slowSelfTestTypes[canonicalHashType(v.typ)] && !*withSlow && *only == "" {
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
	fmt.Printf("\n  %d of %d catalogue types carry a vector; %d do not.\n",
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

// selfTestCoverage splits the printed catalogue into types that have a vector
// and types that do not.  Catalogue entries that are prose rather than a type
// name (the "sha1/sha256/sha512 …" style rows) are skipped.
func selfTestCoverage() (covered, uncovered []string) {
	haveVector := map[string]bool{}
	for _, v := range selfTestVectors {
		haveVector[canonicalHashType(v.typ)] = true
	}
	seen := map[string]bool{}
	for _, group := range hashTypeCatalogue {
		for _, item := range group.items {
			name := strings.Fields(item[0])[0]
			if strings.ContainsAny(name, "/…") || seen[name] {
				continue
			}
			seen[name] = true
			if haveVector[canonicalHashType(name)] {
				covered = append(covered, name)
			} else {
				uncovered = append(uncovered, name)
			}
		}
	}
	sort.Strings(covered)
	sort.Strings(uncovered)
	return covered, uncovered
}
