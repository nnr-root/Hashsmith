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
// Scope: username, plus (via --passwd) the account's GECOS/full-name field —
// JtR also mines that field: "John Smith" yields jsmith, johns, smithj,
// john.smith, johnsmith. An earlier version of this file scoped that out,
// reasoning that shadow2smith's "user:hash" output would need a format
// change to carry the name through. That reasoning was wrong, and the
// mistake is corrected in docs/superpowers/notes/2026-09-01-single-crack-notes.md
// rather than silently dropped: smuggling GECOS into the hash-list format
// would in fact be unsafe, because splitUsername (crack.go) is deliberately
// first-colon-only — some hashes legitimately contain colons (NetNTLMv2,
// salted digests, IKE, ...) — so a third colon-delimited field can't be
// parsed back out unambiguously. Instead, --passwd on the crack command
// reads an /etc/passwd-format file directly (parsePasswdGecos in
// extract_shadow.go) and builds a username -> GECOS map that only
// runSingleCrack consults. shadow2smith's output format, and splitUsername,
// are both completely unchanged.
//
// THE PROPERTY THAT MATTERS: a seed derived from one account — whether from
// its username or its GECOS entry — must never be tried against a different
// account's hash. See runSingleCrack below, which enforces this structurally
// — one target at a time — rather than by filtering after the fact.

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

// gecosSeeds returns the small set of name-derived seeds mined from an
// account's GECOS (real-name) field — the --passwd counterpart to
// singleSeeds' username-derived set. GECOS is comma-separated
// (name,room,work-phone,home-phone,... — see `man 5 passwd`); only the
// FIRST comma-field is a name, so a room number or phone extension in a
// later field never leaks into the seed list.
//
// The name is split into "parts" on whitespace and non-alphanumeric runes
// (splitNameParts, rune-aware so accented names split correctly), and only
// the first two parts are used — keeping the list small and bounded
// regardless of how long the GECOS field is (extra middle names, titles,
// suffixes). All seeds are lowercase: unlike singleSeeds, this does not
// hand-generate uppercase/capitalized variants itself — the rule engine
// (-r) mutates case and appends digits on top of these seeds exactly as it
// does for singleSeeds' output, so duplicating that here would just bloat
// the seed list for no benefit.
//
// existing is the account's username-derived seed set already accumulated
// by the caller (runSingleCrack) — a lowercase candidate already in it is
// skipped, so a name that happens to match the login (or a login component)
// doesn't double the work. A nil or empty existing is fine; every candidate
// is then produced.
//
// Handles the edge cases explicitly: empty GECOS, a GECOS field that is only
// a room/phone with no name (empty first comma-field), a single-word name
// (only the "part alone" seed is produced — there's no second part to pair
// it with), and non-ASCII names. All of these simply shrink or empty the
// result; none of them panic or error.
func gecosSeeds(gecos string, existing map[string]bool) []string {
	name := gecos
	if i := strings.IndexByte(name, ','); i >= 0 {
		name = name[:i]
	}
	parts := splitNameParts(name)
	if len(parts) == 0 {
		return nil
	}

	seen := make(map[string]bool, 8)
	var out []string
	add := func(s string) {
		s = strings.ToLower(s)
		if s == "" || seen[s] || existing[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	first := parts[0]
	add(first) // "john"
	if len(parts) == 1 {
		return out
	}
	last := parts[1]
	add(last) // "smith"

	firstInit := firstRuneLower(first)
	lastInit := firstRuneLower(last)

	add(first + last)       // "johnsmith"
	add(last + first)       // "smithjohn"
	add(firstInit + last)   // "jsmith"
	add(first + lastInit)   // "johns"
	add(last + firstInit)   // "smithj"
	add(first + "." + last) // "john.smith"

	return out
}

// splitNameParts splits a GECOS name field (comma already stripped by the
// caller) into its word components: runs of letters/digits, broken at
// whitespace and any other rune (punctuation like "O'Brien", "Smith, Jr.",
// hyphens, ...). Rune-aware, so accented and other non-ASCII names split
// correctly. Single-rune parts are dropped — middle initials ("J.") add
// noise, not signal, matching splitUsernameComponents' rationale.
func splitNameParts(name string) []string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = nil
		}
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
		} else {
			flush()
		}
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

// firstRuneLower returns the lowercased first rune of s as a string ("John"
// -> "j"), or "" for an empty s.
func firstRuneLower(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return ""
	}
	return strings.ToLower(string(r[0]))
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
//
// When --passwd was given (cc.passwdGecos != nil), each username's seed set
// also gains gecosSeeds mined from that account's GECOS entry, if any — an
// account whose username isn't a key in the map simply contributes none
// (map lookup on a missing key yields "", and gecosSeeds("", ...) is nil),
// so a target absent from --passwd falls back to username-only seeds with
// no special-casing needed here. The GECOS lookup and the crackTargets call
// below both stay keyed to usernamesFor(l.hash) — this account's own
// name(s) only — so a name-derived seed is exactly as isolated to its own
// hash as a username-derived one.
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
			if cc.passwdGecos != nil {
				// cc.passwdGecos[u] is "" both for a genuinely empty GECOS
				// field and for a username absent from --passwd — gecosSeeds
				// handles "" by returning nil, so an account missing from
				// the passwd map simply contributes no extra seeds here
				// rather than skipping or erroring.
				for _, s := range gecosSeeds(cc.passwdGecos[u], seen) {
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
