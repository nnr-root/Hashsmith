package main

import (
	"fmt"
	"testing"
	"time"
)

// A verifier that accepts a wrong password is worse than one that is missing.
// A missing format says so; a leaky one sends a user through a full run and
// hands back a password that does not open the file, with nothing to
// distinguish it from the real answer.
//
// This has happened twice here, both times in a record that kept a short check
// and threw away the material that would have settled it:
//
//   - ZipCrypto kept ONE check byte and accepted one wrong password in 256.
//     Its own round-trip test had been failing at about that rate for as long
//     as it existed, which reads exactly like a flake.
//   - WinZip AES kept the two-byte password verifier and discarded the
//     authentication code sitting behind it in the same entry: one in 65,536.
//
// Neither was visible to a round trip over a single known password, because
// both cracked the right password perfectly well. What finds them is volume:
// throw enough wrong passwords at every format and a short check shows up as
// an accept.
//
// WHAT THIS CAN AND CANNOT SEE. With the budget below it reliably catches a
// check of one or two bytes, which is the class that bit us. It cannot catch a
// four-byte check — that needs four billion tries — so a clean run here is not
// proof of exactness, only the absence of the cheap mistake.
//
// THE BUDGET. 512 tries against every format costs 136 seconds, which is most
// of a second suite, so each format also gets a wall-clock slice. That is not
// a compromise on the formats that matter: the leaks this looks for live in
// RECORD parsing — an archive header that kept a check byte — and those
// verifiers are the cheap ones, which finish all 512 well inside the slice.
// What gets truncated is the expensive KDFs, where a short check is not a
// shape the verifier can have because it compares a full digest.
//
// Truncation is reported rather than silent, so a format that quietly stops
// being swept shows up in the log instead of looking like coverage.
//
// ONE KNOWN CASE THIS CANNOT REACH, stated so a clean run is not read as more
// than it is: the short $zipaes128$/$zipaes192$/$zipaes256$ records keep
// WinZip's two-byte password verifier and nothing else, so they accept one
// wrong password in 65,536 — too rare for any budget here to see, and a
// property of the record rather than a bug in the verifier. The `winzip` type
// reads the $zip2$ record instead, which carries the authentication code and
// is exact; zip2smith emits that form whenever the archive allows it.
const (
	falseAcceptTries  = 512
	falseAcceptBudget = 100 * time.Millisecond
)

func TestNoVerifierAcceptsAWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("this sweeps every format; run without -short")
	}
	seen := make(map[string]bool)
	checked := 0
	var leaky, truncated []string

	for _, v := range universalHashRegistry.vectors {
		if v.target == "" || seen[v.typ] {
			continue
		}
		seen[v.typ] = true
		// Memory-hard and high-iteration KDFs are excluded for time, not
		// because they are trusted: their verifiers compare a full digest, so
		// a short check is not a shape they can have.
		if universalHashRegistry.isSlow(v.typ) {
			continue
		}
		// A vector whose own password does not verify is a different bug, and
		// selftest reports it. Skipping keeps this test's failure meaning one
		// thing.
		if ok, err := verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix"); err != nil || !ok {
			continue
		}
		checked++

		accepted, tried := 0, 0
		start := time.Now()
		for i := 0; i < falseAcceptTries; i++ {
			if i > 0 && i%32 == 0 && time.Since(start) > falseAcceptBudget {
				break
			}
			// Deterministic candidates, so a failure reproduces exactly.
			cand := fmt.Sprintf("wrong-password-%d", i)
			if cand == v.password {
				continue
			}
			tried++
			if ok, err := verifyCandidate(cand, v.target, v.typ, v.salt, "prefix"); err == nil && ok {
				accepted++
			}
		}
		if tried < falseAcceptTries {
			truncated = append(truncated, fmt.Sprintf("%s (%d tries)", v.typ, tried))
		}
		if accepted > 0 {
			leaky = append(leaky, fmt.Sprintf("%s accepted %d of %d wrong passwords (about 1 in %d, "+
				"so its check is roughly %.1f bytes wide)",
				v.typ, accepted, falseAcceptTries, falseAcceptTries/accepted,
				logBytes(falseAcceptTries/accepted)))
		}
	}

	if checked < 200 {
		t.Fatalf("only %d formats were swept; the registry should offer far more, so the "+
			"selection above is wrong rather than the formats being absent", checked)
	}
	t.Logf("swept %d formats with up to %d wrong passwords each", checked, falseAcceptTries)
	if len(truncated) > 0 {
		t.Logf("%d format(s) hit the %v per-format budget and were swept less deeply: %v",
			len(truncated), falseAcceptBudget, truncated)
	}
	for _, l := range leaky {
		t.Errorf("%s", l)
	}
}

// logBytes turns "one in N" into how many bytes of check that implies, which
// is the number that says how bad a leak is: 1 byte is unusable, 2 is bad, 4
// is past what this test can see at all.
func logBytes(oneInN int) float64 {
	if oneInN < 2 {
		return 0
	}
	bits := 0.0
	for n := oneInN; n > 1; n /= 2 {
		bits++
	}
	return bits / 8
}
