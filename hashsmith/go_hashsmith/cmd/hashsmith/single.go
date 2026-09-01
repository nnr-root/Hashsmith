package main

// ── --single: John the Ripper's "single-crack" mode ─────────────────────────
//
// Every other attack mode (dict, brute, mask, hybrid, combinator) generates
// ONE candidate stream shared by every target. Single-crack inverts that: for
// each target that carries a known username (via --username), it derives a
// tiny, DIFFERENT candidate set from that account's login name alone, and
// tries it only against that account's hash. On real engagements this
// out-cracks raw speed — people pick passwords derived from their own login
// (jsmith, Jsmith1, jsmith2024!) — and it is cheap: dozens of candidates
// against one hash, not billions against every target.
//
// Scope: username only. JtR also mines the GECOS/full-name field, but
// shadow2smith discards it today (extract_shadow.go reads /etc/passwd only
// to merge and filter accounts, never carrying the name field through), so
// supporting that needs an output-format change and is out of scope here.
//
// THE PROPERTY THAT MATTERS: a seed derived from one account must never be
// tried against a different account's hash. See runSingleCrack below, which
// enforces this structurally — one target at a time — rather than by
// filtering after the fact.

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// singleSeeds returns the small, per-account seed set that --single feeds to
// the rule engine (via -r/--rules) for one username: the login name itself,
// its common case variants, and its components split on the usual login-name
// separators. Ordered cheapest-first (verbatim before variants), since a hit
// ends the attack for that target. Deduplicated.
//
// An empty or whitespace-only username yields ZERO seeds — never a seed of
// "", which would be tried against that target for no reason. Callers must
// treat a nil/empty result as "no seeds for this account", not an error.
func singleSeeds(username string) []string {
	u := strings.TrimSpace(username)
	if u == "" {
		return nil
	}

	seen := make(map[string]bool, 8)
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// Cheapest-first: the verbatim login name, then its case variants.
	add(u)
	add(strings.ToLower(u))
	add(strings.ToUpper(u))
	add(capitalizeSeed(u))

	// Then its components — "john.smith" also reaches "john" and "smith",
	// a very common password base — each with the same case variants.
	for _, part := range splitUsernameComponents(u) {
		if part == u {
			continue
		}
		add(part)
		add(strings.ToLower(part))
		add(capitalizeSeed(part))
	}

	return out
}

// capitalizeSeed upper-cases the first rune of s and lower-cases the rest —
// "JSMITH" -> "Jsmith", "john" -> "John". Safe on an empty string. Rune-based
// (not byte indexing) so it also does the right thing for non-ASCII logins.
func capitalizeSeed(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + strings.ToLower(string(r[1:]))
}

// splitUsernameComponents breaks a login name at the usual account-name
// separators (., _, -) and at letter/digit boundaries, so "john.smith"
// yields ["john", "smith"] and "jsmith2024" yields ["jsmith", "2024"].
// Single-rune leftovers are dropped — they add noise, not signal, to a seed
// list that is meant to stay small.
func splitUsernameComponents(u string) []string {
	isSep := func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	}

	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = nil
		}
	}

	var prevDigit, havePrev bool
	for _, r := range u {
		if isSep(r) {
			flush()
			havePrev = false
			continue
		}
		d := unicode.IsDigit(r)
		if havePrev && d != prevDigit {
			flush()
		}
		cur = append(cur, r)
		prevDigit = d
		havePrev = true
	}
	flush()

	var out []string
	for _, p := range parts {
		if len([]rune(p)) >= 2 {
			out = append(out, p)
		}
	}
	return out
}

// runSingleCrack runs --single: for every target that carries a known
// username (cc.usernameFor), it builds that account's seed list, writes it as
// a one-off dict-mode wordlist, and calls crackTargets with a slice
// containing ONLY that one target. That last part is what enforces the
// property that matters — a seed derived from account A is never handed to
// crackTargets alongside account B's hash, so there is no shared candidate
// stream for it to leak across. It is called from runCrack BEFORE the main
// attack: single-crack is cheap and high-yield, so trying it first means the
// main attack never re-discovers, at full keyspace cost, what a handful of
// per-account seeds already found.
//
// Like --loopback (see runLoopback), every single-crack pass runs unbounded
// regardless of --skip/--limit: those bound the MAIN attack's keyspace slice
// for distributed cracking, and single-crack's seed list is a separate,
// self-contained candidate source, not a slice of that keyspace.
//
// --show never attacks (its contract: report potfile hits only); --single
// must not reintroduce an attack path there, so it mirrors runLoopback's
// showOnly guard exactly.
//
// Two input lines can share one hash — two accounts with the same weak
// password on an unsalted digest, a real and common shape in dumps (it's
// exactly why multi-hash mode and --loopback exist at all). cc.usernameFor
// only ever returns the LAST-parsed username for a hash, which would derive
// seeds from the wrong account — or, if that account's own login isn't the
// shared password, miss a password that one of the OTHER accounts sharing
// the hash would trivially have found. cc.usernamesFor returns every
// username associated with a hash, so runSingleCrack seeds from all of them
// — each hash is still attacked exactly once, with the union of every
// associated account's seed list, and that union is still tried only
// against the hash it's associated with (isolation from OTHER hashes is
// unaffected: usernamesFor never crosses hash keys).
func runSingleCrack(lines []inputLine, typ string, workers int, salt, saltMode, outFile string,
	copyResult bool, rules *ruleEngine, cc *crackCtx) error {
	if cc == nil || cc.showOnly {
		return nil
	}

	savedSkip, savedLimit := cc.skip, cc.limit
	cc.skip, cc.limit = 0, 0
	defer func() { cc.skip, cc.limit = savedSkip, savedLimit }()

	attacked := 0
	processed := make(map[string]bool, len(lines)) // hash already single-cracked this call
	for _, l := range lines {
		if processed[l.hash] || cc.wasFound(l.hash) {
			continue // already handled — a shared hash needs only one pass
		}
		processed[l.hash] = true

		usernames := cc.usernamesFor(l.hash)
		if len(usernames) == 0 {
			continue // no username on this hash — no seeds to derive it from
		}
		seen := make(map[string]bool, len(usernames)*8)
		var seeds []string
		for _, u := range usernames {
			for _, s := range singleSeeds(u) {
				if !seen[s] {
					seen[s] = true
					seeds = append(seeds, s)
				}
			}
		}
		if len(seeds) == 0 {
			continue
		}
		tmp, err := writeTempWordlist(seeds)
		if err != nil {
			return fmt.Errorf("--single: %w", err)
		}
		attacked++
		// len==1: THE property that matters. This target's seeds — from
		// every account sharing this hash, but ONLY this hash — are tried
		// against this target and no other.
		runErr := crackTargets([]string{l.hash}, typ, "dict", tmp, "", 0, 0, workers,
			salt, saltMode, outFile, copyResult, rules, nil, cc)
		os.Remove(tmp)
		if runErr != nil {
			return fmt.Errorf("--single (user(s) %v): %w", usernames, runErr)
		}
	}
	if attacked > 0 {
		clrGreen.Fprintf(os.Stderr, "Single-crack: tried per-account seeds against %d target(s)\n", attacked)
	}
	return nil
}
