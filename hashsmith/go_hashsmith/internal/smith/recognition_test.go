package smith

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

// recognitionFloor is a ratchet, not a target. Raise it as coverage improves;
// never lower it to make a change pass.
//
// Measured 2026-09-05 on top of base commit 62e2617 (Task 15's own fixes to
// mssql2012, cisco4 and ripemd320 detection applied on top of that base,
// not present at it): 272/502 = 54.18326...%.
// Set to that rate minus 0.01, computed rather than hand-rounded so the
// margin is exact. See docs/superpowers/notes/2026-09-05-recognition-baseline.md.
const recognitionFloor = 272.0/502.0 - 0.01

func TestRecognitionAccuracy(t *testing.T) {
	var total, recognized int
	missed := map[string]string{}

	for _, v := range universalHashRegistry.vectors {
		if v.target == "" {
			continue
		}
		total++
		ok := false
		for _, c := range identifyCandidates(v.target) {
			if c.Suppressed || c.Type != v.typ {
				continue
			}
			if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
				ok = true
			}
			break
		}
		if ok {
			recognized++
		} else if _, dup := missed[v.typ]; !dup {
			missed[v.typ] = v.target
		}
	}

	rate := float64(recognized) / float64(total)
	names := make([]string, 0, len(missed))
	for k := range missed {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("recognition: %d/%d = %.1f%%", recognized, total, rate*100)
	t.Logf("formats not recognized at certain/likely (%d): %s",
		len(names), strings.Join(names, " "))

	if rate < recognitionFloor {
		t.Fatalf("recognition rate %.3f fell below the ratchet %.3f", rate, recognitionFloor)
	}
}

// detectableFloor is a ratchet, not a target: the maximum number of self-test
// vectors whose own type is allowed to be missing from detectHashTypes'
// candidates. It does NOT mean the other vectors ARE detectable — only that
// no more than this many are known NOT to be. Raise the bar by lowering this
// number as detection improves; never raise it to make a change pass.
//
// Re-measured 2026-09-05 immediately after C1's fix (detectTypesFromTable
// filtering non-hash types out of crack's vocabulary): 194, unchanged from
// before that fix, because C1 only removes non-hash candidates (base32,
// morse, nato, ...) that were never a self-test vector's own type to begin
// with.
// Raised from 194 to 196 on 2026-09-20, for three formats added that day.
// Each addition is structural, not a regression in detection:
//
//   - sha256-utf16lepass-salt and sha256-utf16lepass-hexsalt (the latter is
//     Hashcat 13800). This test feeds each vector's BARE digest, and a bare
//     64-character hex string carries nothing that could attribute it to one
//     salted construction over another. In the shape a user actually pastes —
//     digest:salt — both ARE reached, and identify labels the hex-salt one
//     -m 13800.
//
//   - keepass-keyfile (Hashcat 29700). Its record is byte-identical in shape
//     to a keyfile-less KDBX 2/3 record, so nothing in the record can choose
//     between the two readings; only the mode number can. It is deliberately
//     NOT offered by auto-detection: doing so would run a second expensive
//     AES-KDF on every KeePass target, to cover a mode that applies only when
//     a database's sole credential is its keyfile. It is reachable with
//     -t keepass-keyfile or -m 29700.
//
//   - wbb4 (Hashcat 33800). WoltLab Burning Board 4 stores
//     bcrypt(bcrypt($pass)) in an ordinary bcrypt crypt string, so its record
//     is byte-identical in shape to a plain bcrypt one and nothing in it can
//     choose between the two readings. Offering it would double the bcrypt
//     work on EVERY bcrypt target — the slowest common format there is — to
//     cover one forum product. The same trade as keepass-keyfile, and decided
//     the same way. It is reachable with -t wbb4 or -m 33800.
//
//   - pkzip-masterkey (Hashcat 20500). Its record is the ZipCrypto key state
//     written as 24 bare hex characters, with no prefix, no separator and no
//     length that distinguishes it from any other 96-bit value — a truncated
//     digest, a CRC, a MAC fragment. Nothing currently claims 24 hex, so a
//     prototype for it would be the only match and would therefore name every
//     such input a PKZIP key. It is reachable with -t pkzip-masterkey or
//     -m 20500.
//
//   - domino5 (Hashcat 8600). Its record is a bare 32-hex digest, the same
//     shape as MD5, MD4, MD2, NTLM and LM. Offering it there is possible and
//     was tried; TestRawDigestAndBatchable rejected it, and rightly. A 32-hex
//     target with no -t is the most common input this tool sees, and it takes
//     the batched raw-digest path — which every candidate type has to support
//     for the batch to happen at all. Adding one type that does not would cost
//     that path on every bare MD5 to cover a legacy Domino deployment. The
//     same trade as wbb4, decided the same way. It is reachable with -t
//     domino5 or -m 8600.
//
//   - pdf-user-owner (Hashcat 25400). Its record is an ordinary $pdf$ record,
//     already claimed by "pdf", which recovers the USER password from it.
//     Offering this type alongside would make auto-detection redo that user
//     check before trying the owner one, doubling the work on every PDF to
//     reach a credential most callers are not asking for. It is reachable
//     with -t pdf-user-owner or -m 25400.
//
//   - android-fde-samsung (Hashcat 12900). Its record is 160 bare hex
//     characters, the same shape as an Oracle 12c verifier, which already
//     claims it. Offering both was tried; TestOracle12cVector rejected it.
//     Oracle 12c is PBKDF2-SHA512 and Samsung FDE is PBKDF2-SHA256, so every
//     Oracle target would pay a second slow derivation to cover a format it
//     is far more common than. It is reachable with -t android-fde-samsung or
//     -m 12900.
//
//   - md6-256 (Hashcat 34600). Its record is a bare 64-hex digest, the same
//     shape as SHA-256, and unlike domino5 it COULD join that batch: MD6 goes
//     through hashText like any other raw hash. The objection is cost, not
//     structure. One MD6-256 compression is 104 rounds of 16 steps — 1664 word
//     operations against SHA-256's 64 — so it is on the order of a thousand
//     times the work per candidate. Offering it to auto-detection would put
//     that on every bare 64-hex crack, which is one of the most common inputs
//     this tool sees, to cover a SHA-3 candidate that lost in 2009 and is used
//     essentially nowhere. It is reachable with -t md6-256 or -m 34600, and it
//     is a first-class hash for the `hash` side of the tool.
const detectableFloor = 202

// undetectableByDesign names types that must NEVER be reachable from
// auto-detection, and so are excluded from the count above rather than
// raising it.
//
// The distinction matters. The floor covers formats whose records are
// ambiguous — a bare hex digest that could be any of six constructions — and
// every one of those is a gap that could in principle close. These cannot
// close, because a prototype for them would match input that is not theirs:
//
//   - plaintext (Hashcat 99999). Its "record" is the password itself, so any
//     text at all is a valid one. A detection prototype would claim every
//     input Hashsmith is ever given, which would make identify useless. It is
//     reachable with -t plaintext or -m 99999 and only ever deliberately.
//
// Counting these in the floor would quietly buy room for a real detection gap
// to appear later without failing anything.
var undetectableByDesign = map[string]bool{
	"plaintext": true,
}

// Every vector must at least be CRACKABLE by auto-detection, which is a weaker
// and more important property than being confidently named. This test only
// guarantees that the count of vectors failing that property has not grown
// past detectableFloor — it does not guarantee any specific vector passes.
func TestEveryVectorIsDetectableForCracking(t *testing.T) {
	var missing []string
	for _, v := range universalHashRegistry.vectors {
		if v.target == "" || undetectableByDesign[v.typ] {
			continue
		}
		found := false
		for _, typ := range detectHashTypes(v.target) {
			if typ == v.typ {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("%s (%.40s)", v.typ, v.target))
		}
	}
	sort.Strings(missing)
	t.Logf("%d vectors whose own type is not among detectHashTypes' candidates:", len(missing))
	for _, m := range missing {
		t.Log("  " + m)
	}
	if len(missing) > detectableFloor {
		t.Fatalf("%d vectors are not detectable for cracking, exceeding the ratchet of %d",
			len(missing), detectableFloor)
	}
}

// TestNonHashTypesExcludedFromCracking is the regression test for C1: the
// prototype table carries non-hash recognitions (Base32, Morse, NATO, ...)
// so identify can name them, but detectHashTypes/detectTypesFromTable feed
// crack's auto-detection, and crack has no attack routine for any of them.
// Before this test existed, "hashsmith crack -t auto admin" confidently
// misidentified "admin" as base32 and then failed with "unsupported hash
// algorithm: base32" instead of the honest "could not auto-detect" guidance
// — see detectTypesFromTable's crackable() filter in prototypes.go.
//
// The golden corpus (testdata/detect_golden.txt) is 502 hash-shaped vectors
// and contains no ordinary English word, which is exactly why nineteen
// per-task reviews missed this hole; these vectors are deliberately
// non-hash-shaped so they cannot land in that corpus.
func TestNonHashTypesExcludedFromCracking(t *testing.T) {
	nonHashInputs := []string{
		"admin",               // plain word: base32-shaped under a loose Match
		"1 2 3 4 5",           // decimal byte sequence
		"... --- ...",         // Morse code
		"Alpha Bravo Charlie", // NATO phonetic alphabet
	}
	for _, in := range nonHashInputs {
		if got := detectHashTypes(in); len(got) != 0 {
			t.Errorf("detectHashTypes(%q) = %v, want none (crack must never auto-select a non-hash type)", in, got)
		}
		cs := identifyCandidates(in)
		named := false
		for _, c := range cs {
			if !c.Suppressed {
				named = true
				break
			}
		}
		if !named {
			t.Errorf("identifyCandidates(%q) named nothing; identify must keep recognizing non-hash encodings", in)
		}
	}
}

// TestCandidatePrevalenceMatchesTheProtoThatFired is the regression test for
// I4: prevalenceOf (deleted) looked a type up by NAME across the whole
// table and returned the FIRST prototype containing it, not the one that
// actually produced the candidate. krb5tgs is one of nine types that appear
// in more than one prototype with different curated prevalences — the
// etype-23 (Kerberoastable) shape at 30, any other etype at 8 — and the
// etype-23 entry precedes the general one in table order, so the old lookup
// always returned 30 even for a general-etype record. Candidate.Prevalence
// is now copied directly from the firing prototype in the Identify loop, so
// this can no longer happen by construction; this test pins the observable
// behaviour so a future reintroduction of a table-wide lookup is caught.
func TestCandidatePrevalenceMatchesTheProtoThatFired(t *testing.T) {
	general := "$krb5tgs$18$user$realm$abcdef1234567890"
	cs := identifyCandidates(general)
	c := (*hashid.Candidate)(nil)
	for i := range cs {
		if cs[i].Type == "krb5tgs" {
			c = &cs[i]
			break
		}
	}
	if c == nil {
		t.Fatalf("no krb5tgs candidate for %q: %+v", general, cs)
	}
	if c.Prevalence != 8 {
		t.Errorf("krb5tgs (general etype) prevalence = %d, want 8 (the general prototype's own curated value, not the etype-23 prototype's 30)", c.Prevalence)
	}
}

func TestFalsePositives(t *testing.T) {
	notHashes := []string{
		"the quick brown fox jumps over the lazy dog",
		"hello world",
		"550e8400-e29b-41d4-a716-446655440000",
		"/usr/local/bin/hashsmith",
		"1234",
		"{}",
	}
	for _, in := range notHashes {
		for _, c := range identifyCandidates(in) {
			if !c.Suppressed && c.Confidence == hashid.Certain {
				t.Errorf("%q was identified as %s with certainty", in, c.Display)
			}
		}
	}
}
