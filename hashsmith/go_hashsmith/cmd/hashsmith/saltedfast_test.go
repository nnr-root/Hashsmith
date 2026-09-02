package main

// Tests for the salted contiguous-batch fast path (stdfast.go's stdSalt /
// stdSaltedPlanFor, and batch.go's salt grouping).
//
// The organising question throughout is not "did it find something" but "is
// the plaintext it filed against a target actually that target's password".
// For a single salt those two questions coincide; for a dump carrying a
// DIFFERENT salt per target they do not, and a run that mixed the groups up
// would still find every plaintext and still report the right count — it would
// just attach them to the wrong accounts. Every end-to-end test here therefore
// re-derives the digest from the reported plaintext with the reported target's
// OWN salt and mode, and compares that to the target itself.

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// ── 1. the generator: salt || candidate || salt, byte for byte ──────────────

// The salted fill must produce exactly the message hashText would hash: the
// affixes in the right places around the candidate maskIdxToStr decodes, for
// EVERY index of a segment. Enumerating whole segments (rather than sampling)
// is what makes a dropped odometer carry, or a salt written at the wrong
// stride, impossible to miss.
//
// candidate() must simultaneously report the PASSWORD alone — a fill that got
// the message right but handed the salt back as part of the candidate would
// crack correctly and then print the wrong plaintext.
func TestContigFillSaltedMatchesMaskIdxToStr(t *testing.T) {
	segs := [][][]byte{
		{[]byte("ab")},                                              // 2
		{[]byte("abc"), []byte("de")},                               // 6
		{[]byte("abcde"), []byte("xy"), []byte("012")},              // 30
		{[]byte("abc"), []byte("abc"), []byte("abc"), []byte("ab")}, // 54, several carries deep
		{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh"),
			[]byte("ij"), []byte("kl"), []byte("mn")}, // 128 > one batch
	}
	salts := []struct {
		name string
		salt stdSalt
	}{
		{"prefix", stdSalt{pre: []byte("deadbeef")}},
		{"suffix", stdSalt{suf: []byte("deadbeef")}},
		{"one-byte prefix", stdSalt{pre: []byte("$")}},
		{"long prefix", stdSalt{pre: []byte(strings.Repeat("s", stdMaxSaltLen))}},
		{"unsalted", stdSalt{}},
	}
	for _, sc := range salts {
		t.Run(sc.name, func(t *testing.T) {
			cb := newContigBatch(stdBatchGroup, 32, sc.salt)
			pre, suf := string(sc.salt.pre), string(sc.salt.suf)
			for si, sets := range segs {
				total := maskKeyspace(sets)
				for from := int64(0); from < total; from++ {
					for _, want := range []int{1, 3, stdBatchGroup} {
						n := cb.fillFromSegment(sets, from, total, want)
						expect := want
						if int64(expect) > total-from {
							expect = int(total - from)
						}
						if n != expect {
							t.Fatalf("seg %d from=%d want=%d: filled %d, expected %d", si, from, want, n, expect)
						}
						if cb.stride != len(pre)+len(sets)+len(suf) {
							t.Fatalf("seg %d: stride %d, want %d", si, cb.stride, len(pre)+len(sets)+len(suf))
						}
						msgs := cb.messages(n)
						for i := 0; i < n; i++ {
							plain := maskIdxToStr(from+int64(i), sets)
							if got := string(cb.candidate(i)); got != plain {
								t.Fatalf("seg %d from=%d lane %d: candidate %q, maskIdxToStr says %q",
									si, from, i, got, plain)
							}
							got := string(msgs[i*cb.stride : (i+1)*cb.stride])
							if exp := pre + plain + suf; got != exp {
								t.Fatalf("seg %d from=%d lane %d: message %q, want %q", si, from, i, got, exp)
							}
						}
					}
				}
			}
		})
	}
}

// ── 2. the plan: what the fast path hashes is what hashText hashes ──────────

// stdSaltedPlanFor is a transcription of hashText's and
// hashCompatSaltedDigest's concatenation rules; this enumerates both sides and
// compares the resulting digests. It is the check that catches a reversed
// concatenation — the failure a prefix-only test would sail straight past.
func TestStdSaltedPlanMatchesHashText(t *testing.T) {
	cases := []struct{ typ, salt, saltMode string }{
		{"md5", "deadbeef", "prefix"},
		{"md5", "deadbeef", "suffix"},
		{"md5", "deadbeef", ""},       // hashText treats anything but "suffix" as prefix
		{"md5", "deadbeef", "PREFIX"}, // …including a value it does not recognise
		{"sha1", "s@lt-with-symbols", "prefix"},
		{"sha1", "s@lt-with-symbols", "suffix"},
		{"sha256", "0123456789abcdef", "prefix"},
		{"sha256", "0123456789abcdef", "suffix"},
		{"md5-salt-pass", "abc", "suffix"}, // the type fixes the order; -S is ignored
		{"md5-pass-salt", "abc", "prefix"}, // …in both directions
		{"sha1-salt-pass", "abc", "prefix"},
		{"sha1-pass-salt", "abc", "suffix"},
		{"sha256-salt-pass", "abc", "prefix"},
		{"sha256-pass-salt", "abc", "suffix"},
		{"20", "abc", "prefix"}, // hashcat mode numbers resolve to the same plans
		{"110", "abc", "prefix"},
		{"1410", "abc", "prefix"},
		{"md5", strings.Repeat("x", stdMaxSaltLen), "prefix"},
	}
	plains := []string{"a", "abc", "password123", strings.Repeat("q", 55), strings.Repeat("r", 100)}
	for _, c := range cases {
		algo, sp, ok := stdSaltedPlanFor(c.typ, c.salt, c.saltMode)
		if !ok {
			t.Errorf("%s/%s: no plan", c.typ, c.saltMode)
			continue
		}
		for _, p := range plains {
			msg := string(sp.pre) + p + string(sp.suf)
			out := make([]byte, algo.digLen)
			algo.hashBatch([]byte(msg), len(msg), 1, out)
			want, err := hashText(p, c.typ, c.salt, c.saltMode)
			if err != nil {
				t.Fatalf("hashText(%s): %v", c.typ, err)
			}
			if got := hex.EncodeToString(out); got != want {
				t.Errorf("%s/%s(%q): fast path %s, hashText %s", c.typ, c.saltMode, p, got, want)
			}
		}
	}
}

// The affixes must not be interchangeable: a plan built for prefix must not
// produce the suffix digest, or the "both modes" coverage above would be
// satisfied by a path that ignored -S entirely.
func TestStdSaltedPlanDistinguishesPrefixFromSuffix(t *testing.T) {
	const salt, plain = "deadbeef", "abc"
	for _, typ := range []string{"md5", "sha1", "sha256"} {
		_, pre, ok1 := stdSaltedPlanFor(typ, salt, "prefix")
		_, suf, ok2 := stdSaltedPlanFor(typ, salt, "suffix")
		if !ok1 || !ok2 {
			t.Fatalf("%s: missing a plan", typ)
		}
		a := string(pre.pre) + plain + string(pre.suf)
		b := string(suf.pre) + plain + string(suf.suf)
		if a == b {
			t.Errorf("%s: prefix and suffix hash the same message %q", typ, a)
		}
		if a != salt+plain {
			t.Errorf("%s prefix message %q, want %q", typ, a, salt+plain)
		}
		if b != plain+salt {
			t.Errorf("%s suffix message %q, want %q", typ, b, plain+salt)
		}
	}
}

// ── 3. the runner: same answers as the scalar path ──────────────────────────

// A salted multi-target pass must credit every owner of a digest and report
// the plaintext, not the salted message. Driven through batchStdLayout, the
// same entry point runBatch uses.
func TestBatchStdLayoutSalted(t *testing.T) {
	for _, c := range []struct{ typ, salt, saltMode string }{
		{"md5", "deadbeef", "prefix"},
		{"md5", "deadbeef", "suffix"},
		{"sha1", "pepper", "prefix"},
		{"sha256", "pepper", "suffix"},
		{"md5-salt-pass", "pepper", "prefix"},
	} {
		t.Run(c.typ+"/"+c.saltMode, func(t *testing.T) {
			plains := []string{"aaa", "mnq", "zzz"}
			var batch []*batchTarget
			for _, p := range plains {
				h, err := hashText(p, c.typ, c.salt, c.saltMode)
				if err != nil {
					t.Fatal(err)
				}
				batch = append(batch, &batchTarget{norm: h, key: h, orig: h, salt: c.salt})
			}
			// A second target sharing the first's digest: both owners must be
			// credited from the single lookup.
			batch = append(batch, &batchTarget{norm: batch[0].norm, key: batch[0].key,
				orig: "dup", salt: c.salt})

			got := map[string]string{}
			var mu atomic.Int32
			record := func(pw string, idxs []int) bool {
				for _, i := range idxs {
					got[batch[i].orig] = pw
				}
				return int(mu.Add(int32(len(idxs)))) >= len(batch)
			}
			var attempts int64
			l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
			if !batchStdLayout(context.Background(), c.typ, l, allIdx(len(batch)), batch,
				c.salt, c.saltMode, 0, 0, 4, &attempts, nil, record) {
				t.Fatal("batchStdLayout declined an eligible salted pass")
			}
			for i, p := range plains {
				if got[batch[i].orig] != p {
					t.Errorf("target %d: got %q, want %q", i, got[batch[i].orig], p)
				}
			}
			if got["dup"] != plains[0] {
				t.Errorf("duplicate digest not credited: got %q", got["dup"])
			}
		})
	}
}

// batchStdLayout must refuse a pass whose targets do not all share the salt it
// was handed. That combination cannot arise from runBatch (which groups first),
// and the refusal is what keeps it from arising from anything else: hashing one
// candidate for a mixed group would compare digests salted with A against
// targets salted with B and file whatever collided.
func TestBatchStdLayoutRefusesMixedSalts(t *testing.T) {
	h1, _ := hashText("mnq", "md5", "one", "prefix")
	h2, _ := hashText("mnq", "md5", "two", "prefix")
	batch := []*batchTarget{
		{norm: h1, key: h1, orig: h1, salt: "one"},
		{norm: h2, key: h2, orig: h2, salt: "two"},
	}
	var attempts int64
	called := false
	if batchStdLayout(context.Background(), "md5", bruteLayout("abc", 3, 3), allIdx(2), batch,
		"one", "prefix", 0, 0, 2, &attempts, nil,
		func(string, []int) bool { called = true; return true }) {
		t.Error("batchStdLayout accepted a mixed-salt group")
	}
	if called || attempts != 0 {
		t.Errorf("a declined pass recorded %v / counted %d attempts", called, attempts)
	}
}

// --skip/--limit must slice a salted run exactly as they slice an unsalted
// one: the union of two adjacent slices is the whole keyspace, and neither
// slice alone finds a plaintext that lives in the other.
func TestSaltedFastPathHonoursSkipAndLimit(t *testing.T) {
	const salt = "deadbeef"
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3) // 17576
	half := l.total / 2
	for _, c := range []struct {
		name  string
		plain string
		lo    bool // lives in the low half
	}{
		{"low half", "aab", true},
		{"high half", "zzy", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			target, err := hashText(c.plain, "md5", salt, "prefix")
			if err != nil {
				t.Fatal(err)
			}
			run := func(from, limit int64) string {
				var attempts int64
				pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, from, limit, 4, &attempts,
					"md5", salt, "prefix", target, func(cand string) bool {
						ok, _ := verifyCandidate(cand, target, "md5", salt, "prefix")
						return ok
					})
				if err != nil {
					t.Fatal(err)
				}
				return pw
			}
			lo, hi := run(0, half), run(half, 0)
			if c.lo {
				if lo != c.plain || hi != "" {
					t.Errorf("low=%q high=%q, want %q and \"\"", lo, hi, c.plain)
				}
			} else {
				if hi != c.plain || lo != "" {
					t.Errorf("low=%q high=%q, want \"\" and %q", lo, hi, c.plain)
				}
			}
		})
	}
}

// ── 4. end to end ───────────────────────────────────────────────────────────

// saltedRun cracks `lines` with the given flags and returns the -o file's
// "target:plaintext" pairs as a map, in file order.
func saltedRun(t *testing.T, lines []string, words []string, args ...string) (map[string]string, []string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, strings.Join(words, "\n")+"\n")
	tf := filepath.Join(dir, "targets.txt")
	mustWrite(t, tf, strings.Join(lines, "\n")+"\n")
	out := filepath.Join(dir, "out.txt")

	full := append([]string{"-M", "dict", "-w", wl, "--no-pot", "-o", out}, args...)
	full = append(full, tf)
	exitCode = 0
	if err := runCrack(full); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return map[string]string{}, nil
	}
	// The multi-target path writes "target:plaintext"; the single-target path
	// writes the plaintext alone. Match each line against the input targets
	// rather than guessing at the colon, since a hash:salt target contains one.
	pairs := map[string]string{}
	var order []string
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if l == "" {
			continue
		}
		matched := false
		for _, tgt := range lines {
			if strings.HasPrefix(l, tgt+":") {
				pairs[tgt] = l[len(tgt)+1:]
				order = append(order, tgt)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if len(lines) == 1 {
			pairs[lines[0]] = l
			order = append(order, lines[0])
			continue
		}
		t.Fatalf("unparseable -o line %q", l)
	}
	return pairs, order
}

// mustAttribute re-derives each reported target's digest from the plaintext it
// was filed against, using THAT target's own salt and mode, and fails when it
// does not match. Counting recoveries cannot catch a mis-grouped dump; this
// can.
func mustAttribute(t *testing.T, pairs map[string]string, typ, saltMode string, saltOf map[string]string) {
	t.Helper()
	for target, plain := range pairs {
		salt := saltOf[target]
		ok, err := verifyCandidate(plain, target, typ, salt, saltMode)
		if err != nil {
			t.Fatalf("verifyCandidate(%q, %q): %v", plain, target, err)
		}
		if !ok {
			t.Errorf("MIS-ATTRIBUTED: %q filed against %s (salt %q) but does not hash to it", plain, target, salt)
		}
	}
}

// The three shapes the brief names, each compared against the scalar path on
// identical input: the fast and scalar runners must recover the same pairs, in
// the same order.
func TestSaltedEndToEndMatchesScalarPath(t *testing.T) {
	words := []string{"password", "admin", "letmein", "qwerty", "dragon", "unused"}

	shapes := []struct {
		name  string
		typ   string
		mode  string // -S
		build func() (lines []string, saltOf map[string]string, args []string)
	}{
		{
			name: "single target, -s prefix",
			typ:  "md5", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("password", "md5", "deadbeef", "prefix")
				return []string{h}, map[string]string{h: "deadbeef"},
					[]string{"-t", "md5", "-s", "deadbeef", "-S", "prefix"}
			},
		},
		{
			name: "single target, -s suffix",
			typ:  "md5", mode: "suffix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("password", "md5", "deadbeef", "suffix")
				return []string{h}, map[string]string{h: "deadbeef"},
					[]string{"-t", "md5", "-s", "deadbeef", "-S", "suffix"}
			},
		},
		{
			name: "dump sharing one salt, prefix",
			typ:  "sha1", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for _, w := range words[:5] {
					h, _ := hashText(w, "sha1", "shared-salt", "prefix")
					lines = append(lines, h)
					saltOf[h] = "shared-salt"
				}
				return lines, saltOf, []string{"-t", "sha1", "-s", "shared-salt", "-S", "prefix"}
			},
		},
		{
			name: "dump sharing one salt, suffix",
			typ:  "sha256", mode: "suffix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for _, w := range words[:5] {
					h, _ := hashText(w, "sha256", "shared-salt", "suffix")
					lines = append(lines, h)
					saltOf[h] = "shared-salt"
				}
				return lines, saltOf, []string{"-t", "sha256", "-s", "shared-salt", "-S", "suffix"}
			},
		},
		{
			// The one that matters: five accounts, five different salts,
			// carried in the target lines themselves.
			name: "dump with distinct per-target salts (hashcat 20)",
			typ:  "md5-salt-pass", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for i, w := range words[:5] {
					salt := fmt.Sprintf("salt%d", i)
					d, _ := hashCompatSaltedDigest(w, "md5-salt-pass", salt)
					line := d + ":" + salt
					lines = append(lines, line)
					saltOf[line] = ""
				}
				return lines, saltOf, []string{"-t", "md5-salt-pass"}
			},
		},
		{
			name: "dump with distinct per-target salts (hashcat 110)",
			typ:  "sha1-pass-salt", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for i, w := range words[:5] {
					salt := fmt.Sprintf("s%d", i)
					d, _ := hashCompatSaltedDigest(w, "sha1-pass-salt", salt)
					line := d + ":" + salt
					lines = append(lines, line)
					saltOf[line] = ""
				}
				return lines, saltOf, []string{"-t", "sha1-pass-salt"}
			},
		},
		{
			// Two accounts share a salt, a third does not: the grouping must
			// batch the pair and still sweep for the singleton.
			name: "mixed: two targets share a salt, one differs",
			typ:  "md5-pass-salt", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for i, w := range words[:3] {
					salt := "shared"
					if i == 2 {
						salt = "lonely"
					}
					d, _ := hashCompatSaltedDigest(w, "md5-pass-salt", salt)
					line := d + ":" + salt
					lines = append(lines, line)
					saltOf[line] = ""
				}
				return lines, saltOf, []string{"-t", "md5-pass-salt"}
			},
		},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			lines, saltOf, args := sh.build()

			t.Setenv("HASHSMITH_NO_FASTPATH", "")
			fastPairs, fastOrder := saltedRun(t, lines, words, args...)
			t.Setenv("HASHSMITH_NO_FASTPATH", "1")
			slowPairs, slowOrder := saltedRun(t, lines, words, args...)
			t.Setenv("HASHSMITH_NO_FASTPATH", "")

			if len(fastPairs) != len(lines) {
				t.Fatalf("fast path recovered %d of %d targets: %v", len(fastPairs), len(lines), fastPairs)
			}
			if strings.Join(fastOrder, ",") != strings.Join(slowOrder, ",") {
				t.Errorf("order differs:\n fast %v\n slow %v", fastOrder, slowOrder)
			}
			for k, v := range fastPairs {
				if slowPairs[k] != v {
					t.Errorf("target %s: fast %q, scalar %q", k, v, slowPairs[k])
				}
			}
			mustAttribute(t, fastPairs, sh.typ, sh.mode, saltOf)
		})
	}
}

// The -S mode must reach the batch path. Cracking a suffix-salted dump while
// telling the tool "prefix" must find nothing — if it finds everything, the
// salt mode is being ignored somewhere between the flag and the generator.
func TestSaltedEndToEndRespectsSaltMode(t *testing.T) {
	words := []string{"password", "admin", "letmein"}
	var lines []string
	for _, w := range words {
		h, _ := hashText(w, "md5", "deadbeef", "suffix")
		lines = append(lines, h)
	}
	pairs, _ := saltedRun(t, lines, words, "-t", "md5", "-s", "deadbeef", "-S", "prefix")
	if len(pairs) != 0 {
		t.Errorf("a suffix-salted dump was cracked as prefix: %v", pairs)
	}
	pairs, _ = saltedRun(t, lines, words, "-t", "md5", "-s", "deadbeef", "-S", "suffix")
	if len(pairs) != len(lines) {
		t.Errorf("suffix run recovered %d of %d: %v", len(pairs), len(lines), pairs)
	}
}

// A dump whose targets share a salt is ONE pass — it must not silently become
// one pass per target. Asserted through the run's own attempt accounting: a
// per-target sweep of the same wordlist would count len(targets) times as many
// attempts.
func TestSharedSaltDumpIsOnePass(t *testing.T) {
	const salt = "shared"
	words := []string{"password", "admin", "letmein", "qwerty"}
	var lines []string
	for _, w := range words {
		h, _ := hashText(w, "md5", salt, "prefix")
		lines = append(lines, h)
	}
	batch := make([]*batchTarget, len(lines))
	for i, h := range lines {
		batch[i] = &batchTarget{norm: h, key: h, orig: h, salt: salt}
	}
	var found atomic.Int32
	record := func(string, []int) bool { return int(found.Add(1)) >= len(batch) }
	var attempts int64
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 1, 3)
	if !batchStdLayout(context.Background(), "md5", l, allIdx(len(batch)), batch,
		salt, "prefix", 0, 0, 4, &attempts, nil, record) {
		t.Fatal("batchStdLayout declined a shared-salt pass")
	}
	// Every candidate is hashed once for all four targets, so the pass can
	// never exceed the keyspace even though it is looking for four plaintexts.
	if attempts > l.total {
		t.Errorf("shared-salt pass counted %d attempts over a keyspace of %d — "+
			"that is more than one sweep, so candidates are not being shared",
			attempts, l.total)
	}
}

// A session must checkpoint and resume a salted brute run exactly as it does
// an unsalted one: the fast path publishes the same watermark.
func TestSaltedSessionResumes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const salt, plain = "deadbeef", "zzy"
	target, err := hashText(plain, "md5", salt, "prefix")
	if err != nil {
		t.Fatal(err)
	}
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
	sess := &sessionState{
		Name: "salted-fastpath-resume", Mode: "brute", Type: "md5", Target: target,
		Charset: "abcdefghijklmnopqrstuvwxyz", MinLen: 3, MaxLen: 3,
		Salt: salt, SaltMode: "prefix",
		path: filepath.Join(t.TempDir(), "s.json"),
	}
	var attempts int64
	pw, _, err := runBruteOrMaskLayout(context.Background(), l, sess, 0, 0, 4, &attempts,
		"md5", salt, "prefix", target, func(c string) bool {
			ok, _ := verifyCandidate(c, target, "md5", salt, "prefix")
			return ok
		})
	if err != nil {
		t.Fatal(err)
	}
	if pw != plain {
		t.Fatalf("got %q, want %q", pw, plain)
	}
	if sess.Total != l.total {
		t.Errorf("session Total %d, want %d", sess.Total, l.total)
	}
	if sess.Checkpoint < 0 || sess.Checkpoint > l.total {
		t.Errorf("session Checkpoint %d out of range 0..%d", sess.Checkpoint, l.total)
	}
}

// ── 5. what must NOT change ─────────────────────────────────────────────────

// The salted admission gate must stay narrow. An auto-detected dump, a
// structured record, a UTF-16LE variant and a digest with no batch core all
// keep the per-target path, where they work today.
func TestSaltedBatchTypeIsNarrow(t *testing.T) {
	for _, c := range []struct{ typ, salt, saltMode, want string }{
		{"md5", "s", "prefix", "md5"},
		{"md5", "s", "suffix", "md5"},
		{"sha1", "s", "prefix", "sha1"},
		{"sha256", "s", "prefix", "sha256"},
		{"md5-salt-pass", "", "prefix", "md5-salt-pass"}, // salt comes from hash:salt
		{"20", "", "prefix", "md5-salt-pass"},            // hashcat mode number
		{"md5", "", "prefix", ""},                        // unsalted: the raw-digest path owns it
		{"", "s", "prefix", ""},                          // no -t: auto-detection stays per target
		{"auto", "s", "prefix", ""},
		{"sha512", "s", "prefix", ""},                // no batch core
		{"md5-utf16le-pass-salt", "s", "prefix", ""}, // different message
		{"bcrypt", "s", "prefix", ""},
		{"sha512crypt", "s", "prefix", ""},
		{"md5crypt", "s", "prefix", ""},
		{"phpass", "s", "prefix", ""},
	} {
		if got := saltedBatchType(c.typ, c.salt, c.saltMode); got != c.want {
			t.Errorf("saltedBatchType(%q, %q, %q) = %q, want %q", c.typ, c.salt, c.saltMode, got, c.want)
		}
	}
}

// batchSaltGroups is what turns "one dump" into "one pass per distinct salt";
// its order is the order the passes run in and the order results come back.
func TestBatchSaltGroups(t *testing.T) {
	mk := func(salts ...string) []*batchTarget {
		var b []*batchTarget
		for _, s := range salts {
			b = append(b, &batchTarget{salt: s})
		}
		return b
	}
	for _, c := range []struct {
		name string
		in   []*batchTarget
		want []string
	}{
		{"unsalted dump", mk("", "", ""), []string{""}},
		{"one shared salt", mk("a", "a", "a"), []string{"a"}},
		{"distinct salts, first-seen order", mk("b", "a", "c", "a", "b"), []string{"b", "a", "c"}},
		{"empty batch", nil, nil},
	} {
		got := batchSaltGroups(c.in)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// An unsalted dump must still be a single pass with an empty salt group — the
// grouping must not have turned every existing multi-hash run into something
// else.
func TestUnsaltedDumpStillOneGroup(t *testing.T) {
	words := []string{"password", "admin", "letmein"}
	var lines []string
	for _, w := range words {
		lines = append(lines, md5hex(w))
	}
	pairs, _ := saltedRun(t, lines, words, "-t", "md5")
	if len(pairs) != len(lines) {
		t.Fatalf("recovered %d of %d: %v", len(pairs), len(lines), pairs)
	}
	for target, plain := range pairs {
		if md5hex(plain) != target {
			t.Errorf("MIS-ATTRIBUTED: %q filed against %s", plain, target)
		}
	}
}
