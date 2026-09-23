# Beating John and Hashcat: Measured Gap Analysis and Roadmap

**Date:** 2026-09-20
**Status:** Phases 0, 1, 3 and 6 complete. Phase 2 complete except for the 69
modes still unimplemented, down from 83 — four of which were never hash
algorithms. Phase 4 done, including the rule engine, which now reads 98.4% of
john.conf against john itself. Phase 5 and 7 in progress.

The figures below are the ORIGINAL measurements, kept as they were taken. §8's
progress log carries the current ones and says what moved.

**Machine:** Apple M2 (4P+4E), 16 GB, darwin/arm64, Go 1.26.3
**Comparators:** `hashcat` v7.1.2, `john` 1.9.0-jumbo-1 (ASIMD, MD4:2 MD5:2 interleaving)
**Binary under test:** built from `d91a400` (`go build ./cmd/hashsmith`)

> **Provenance discipline.** Every number in §1-§3 was measured in this session
> and the command that produced it is given. Findings sourced from automated
> analysis but **not** re-verified are quarantined in §4 and labelled
> UNVERIFIED — they are leads, not facts. Claims that were checked and found
> **wrong** are recorded in §5 rather than quietly dropped.
>
> The machine carried load average 7.7-9.3 from unrelated work throughout the
> performance measurements in §3. Those figures are directional.

---

## 1. The headline number: coverage against Hashcat's own ground truth

`hashcat --example-hashes` publishes, for all 581 modes, a canonical record and
the password that cracks it. 538 of those carry a `plain`-format example. Every
one was fed to Hashsmith as `crack -t <mode> <record> -w <4-word list>` where the
list contained the correct password plus three decoys.

| Outcome | Modes | Share |
|---|---|---|
| **CRACKED** — correct password recovered | **418** | **77.7%** |
| **NO-SUCH-MODE** — `unsupported hash algorithm: <n>` | 83 | 15.4% |
| **REJECTED** — mode resolves, canonical record refused by the parser | 30 | 5.6% |
| **NOT-FOUND** — record parses, KDF runs, correct password reported missing | 7 | 1.3% |

> **CORRECTION, 2026-09-20.** An earlier version of this table reported 324
> cracked (60.2%) and 124 rejected (23.0%). Those numbers were wrong, and wrong
> against Hashsmith's interest in the first instance and in its favour in the
> second. `hashcat --example-hashes` **truncates 177 of its own records** in its
> default output, marking each with `[Truncated, use --mach for full length]`.
> Feeding those to a parser measures the truncation, not the parser. The
> corpus is now built from `--example-hashes --mach`, whose JSON is complete —
> the largest record is a 513,152-character VeraCrypt volume header. Every
> figure in this section is from the corrected corpus. The error is recorded
> rather than quietly overwritten because a measurement this document leans on
> has to show its own failures too.

Reproduce: `go test -run TestHashcatConformance -v ./cmd/hashsmith`. The
corpus and the pinned per-mode baseline are checked in under
`cmd/hashsmith/testdata/`, and the test is a ratchet: a mode recorded as
CRACKED must keep cracking.

A further 14 modes (VeraCrypt RIPEMD-160, Whirlpool and Streebog-512 variants)
do crack but exceed the harness's 20-second per-record bound on this machine.
They are classified TIMEOUT and are counted in the 418 above, because an
unbounded run recovers every one of them.

**Read this against the README.** The README's comparison table claims 457
universal formats and 503 numeric Hashcat aliases against Hashcat's "450+".
That framing counts registry entries. Measured against the only test Hashcat
itself supplies, Hashsmith handles 77.7% of Hashcat's modes — a strong result,
and one worth stating in these terms rather than as a registry count, because
this is the number a user experiences.

### 1.1 The 30 rejections are concentrated, not scattered

| Parser | Modes refused |
|---|---|
| **LUKS v1** (29511-29543, every hash/cipher pairing) | **12** |
| Episerver, MongoDB SCRAM, Python Werkzeug | 2 each |
| PostgreSQL, Juniper ScreenOS, Oracle 11+, DNSSEC NSEC3, Blockchain My Wallet, RAR5, AxCrypt 1 SHA-1, iTunes backup >= 10, Skip32, Ansible Vault, Bitwarden, NetNTLMv2 (NT) | 1 each |

One parser — LUKS v1 — is 40% of the rejected set, and all twelve of its modes
differ only in hash and cipher choice. A handful of parser fixes clears most of
this column. This is the cheapest coverage in the entire document.

A small number are legitimate record-shape differences rather than defects
(hashcat's `-m 12` PostgreSQL example carries the username differently than
Hashsmith expects). Most are not.

### 1.2 The 7 silent failures are the most serious class

These parse, run the KDF, and report "Not found" for the password Hashcat says
is correct. A user cannot distinguish this from an uncrackable password.

```
-m 23     Skype
-m 131    MSSQL (2000)
-m 9500   MS Office 2010
-m 12800  MS-AzureSync PBKDF2-HMAC-SHA256
-m 13400  KeePass (KDBX v2/v3)
-m 13800  Windows Phone 8+ PIN/password
-m 29700  KeePass (KDBX v2/v3) - keyfile only
```

Verified by hand for `-m 131` with the correct password `HASHCAT`:

```
$ hashsmith -N crack -t 131 0x0100778883860000...96939 -w w.txt --no-pot
Attempts: 2 | Elapsed: 0.01s | Rate: 375.04 H/s
Not found
```

---

## 2. Confirmed defects

Each was reproduced directly against the built binary.

### 2.1 The CLI input pipeline silently rewrites the user's input

This single subsystem causes failures across `encode`, `decode`, `hash`, `crack`
and `identify`. It is the highest value-per-line-changed work in this document.

| # | Defect | Reproduction | Consequence |
|---|---|---|---|
| A | Any input containing a comma is split into several inputs | `encode -t base64 "a,b"` emits `YQ==` and `Yg==` | 6 Hashcat modes fail as an argument but succeed from a file; every ASCII85/basE91 payload corrupts |
| B | Leading and trailing whitespace is stripped | `encode -t base64 "  padded  "` emits `cGFkZGVk` | quoted-printable cannot emit the `=20` it exists for; no password with edge whitespace is crackable |
| C | Any input starting with `-` is parsed as a flag | `encode -t base64 "-hello"` → `flag provided but not defined` | Morse, ROT47 and PEM payloads are unreachable |
| D | No stdin anywhere; `-` is taken literally | `echo hi \| hashsmith encode -t base64 -` emits `LQ==` (that is `-`) | the tool cannot appear in a pipeline |
| E | A piped wordlist loses the first two bytes of its first word | `printf 'password\nabcdef\n' \| hashsmith crack ... -w /dev/stdin --stdout` emits `ssword`, `abcdef` | piped candidate streams silently skip a password; the file-based control cracks it |
| F | The normalizer rewrites the target **even when `-t` names the type** | `crack -t descrypt 24leDr0hHfb3A` → `Detected Base32hex encoded hash — normalizing to hex` → `invalid descrypt hash` | Hashcat's canonical descrypt record is uncrackable by name or by mode |

Defect F is worth stating plainly: `-t descrypt` is the user declaring the
format, and the tool overrules them and corrupts the input.

### 2.2 Operational gaps

| Defect | Evidence |
|---|---|
| `crack` writes **zero bytes to stdout** — results go to stderr | `crack ... > out.txt` produces a 0-byte file while stderr shows `Found: password` |
| No `--version` and no `version` command | `hashsmith --version` prints the banner and exits 0 |
| Per-command help is broken | `crack --help` → `Error: flag: help requested` |
| No rule files ship | `find . -name '*.rule'` → 0 results. `--rules best64.rule` has nothing to point at |

### 2.3 The default wordlist is an English dictionary, not a password list

`common.txt`, 230,930 lines, is the fallback whenever no rockyou is found:

- **100.0%** of entries are pure lowercase alpha (230,878 / 230,931)
- **51** entries contain a digit (0.0%)
- After roughly the first 50 real passwords it becomes an alphabetical dictionary
  (`alderwoman`, `dendrolite`, `narcotherapy`, ... `zythum`, `zyzomys`)

Rockyou's value is that it is real leaked passwords with digits, capitals and
symbols. An alphabetised dictionary is close to worthless against real hashes,
and it is what a first-time user gets by default.

### 2.4 The self-test cannot see any of this

```
$ hashsmith -N selftest
Self-test: 356/356 vectors passed
  457 of 457 crackable formats carry a vector; 0 do not.
```

Green, while `crack -t descrypt` fails on Hashcat's canonical descrypt record.
The vectors assert at the library layer and never traverse the CLI input
pipeline that corrupts the target. `hash -t descrypt` does not exist at all
(`unsupported hash algorithm: descrypt`), so no round-trip covers it either.

**The self-test is the project's proudest artifact and it is measuring the wrong
boundary.** Fixing that is the precondition for trusting any coverage claim.

### 2.5 John's rule dialect is effectively unsupported

Hashsmith implements Hashcat's rule set well. Against Hashcat's stock files:

| File | Rules | Parse failures |
|---|---|---|
| `toggles1.rule` | 15 | 0 |
| `leetspeak.rule` | 17 | 0 |
| `rockyou-30000.rule` | 30,000 | **0** |

Against John's own `[List.Rules:Wordlist]` section of `john.conf`: **25 of 26
lines fail**, a 3.8% accept rate. Only the no-op `:` loads.

```
line 2: -c >3 !?X l Q       ✗ command "-": bad position "c"
line 4: <* >2 !?A l p       ✗ command "<": bad position "*"
line 7: <7 >1 !?A l d       ✗ unknown rule command "A"
```

Missing: John's reject flags (`-c`, `-8`, `-s`), `*` and `@` length references,
and character classes (`?A`, `?X`, `?v`). The README's claim to speak both
dialects holds for type names; it does not hold for rule files.

### 2.6 Extractors: 62 John converters have no counterpart

John ships **103** `*2john` tools. Hashsmith ships **47** `*2smith`. Absent,
grouped by what a working engagement actually hits:

- **Kerberos:** `krb`, `kirbi`, `ccache`, `kdcdump`
- **Network capture:** `pcap`, `wpapcap`, `hccap`, `radius`, `sipdump` (partial)
- **Keys and certs:** `putty`, `openssl`, `pem`, `pgpdisk`, `pgpsda`, `pgpwde`
- **Java / enterprise:** `keystore`, `bks`, `racf`, `cracf`, `sap`, `lotus`, `ps_token`, `pse`
- **Windows:** `DPAPImk`, `mcafee_epo`
- **Disk:** `androidfde`, `bestcrypt`, `diskcryptor`, `ecryptfs`, `geli`, `openbsd_softraid`, `vdi`
- **Password managers / wallets:** `dashlane`, `enpass`, `padlock`, `keyring`, `kwallet`, `bitshares`, `neo`, `tezos`, `money`
- **Apple / office:** `iwork`, `libreoffice`, `staroffice`, `lion`, `mac`, `strip`
- Plus `aem`, `andotp`, `apex`, `adxcsouf`, `axcrypt`, `deepsound`, `ejabberd`, `filezilla`, `htdigest`, `ibmiscanner`, `known_hosts`, `mongodb`, `network`, `uaf`

John supports **349** formats to Hashsmith's 457 registry entries. John's moat is
not format count — it is that its long tail is reachable, because a converter
exists for the file you actually hold.

### 2.7 Packaging: no install path delivers current code

| Path | State |
|---|---|
| **pip wheel** | Cannot build. `setup.cfg` `package_data` lists only `go_hashsmith/cmd/hashsmith/*.go` and `*.txt`; it omits every `internal/` package (`bcryptlane`, `argon2d`, `gpubackend`, `hashid`) the CLI imports |
| **pip sdist** | Cannot build on amd64 or arm64. `MANIFEST.in` ships `*.go`, `go.mod`, `go.sum`, `*.txt` — never the four `.s` assembly files the vector cores need |
| **npm** | Requires a Go toolchain at install; `--ignore-scripts` bricks it |
| **Homebrew** | Third-party tap, builds from source, pinned to a stale tag |
| **Releases** | 3 tags total, newest `v1.2.0`. Zero prebuilt binaries anywhere |

The comparison table advertises "Install: one static binary, no runtime deps".
No user can obtain that binary today.

---

## 3. Performance: where Hashsmith actually stands

Best-of-kept after discarding a warm-up run, machine load 7.7-9.3 throughout.

### 3.1 CPU — Hashsmith wins, and the SIMD work is why

MD5, 5-character lowercase brute, keyspace 11,881,376, target absent:

| | Rate |
|---|---|
| Hashsmith, 8 workers | **118.8 MH/s** |
| John `raw-md5`, `--test=5`, single thread | 10.46 MH/s |
| John extrapolated to 8 forks | ~83.7 MH/s |

Hashsmith is roughly **1.4x John** on CPU MD5. The AVX2/NEON core investment
paid off and should be stated as a win.

### 3.2 GPU — the backends work, and they deliver almost nothing

Both build and self-test clean:

```
$ hashsmith-gpu -N gpu
GPU acceleration: available — Metal (Apple M2)
  self-test: MD5, MD4, NTLM, SHA-1 and SHA-256 mask kernels match CPU ✓
  in-kernel brute: cracked "zzzzz" in 0.09s — 132.35 MH/s (candidate gen on GPU)
```

| | MD5 rate |
|---|---|
| Hashsmith CPU, 8 workers | 118.8 MH/s |
| Hashsmith GPU, Metal (`-tags gpu`) | 132.4 MH/s |
| Hashsmith GPU, OpenCL (`-tags opencl`) | 189.2 MH/s |
| **Hashcat, same GPU** | **2047.7 MH/s** |

Two facts follow, and both are uncomfortable:

1. **Hashsmith's GPU is 10.8x behind Hashcat on the same silicon** (189 vs 2048).
2. **Hashsmith's GPU is only 1.6x its own CPU.** Hashcat's GPU is 17x Hashsmith's
   CPU. A backend that costs cgo, two build tags, a CI job and a kernel language
   buys a 1.6x multiple over code the project already has.

`-tags gpu` selects Metal on macOS, which is the **slower** of the two backends
(132 vs 189 MH/s, 1.43x). That default is backwards.

---

## 4. Leads not yet verified

Automated analysis produced 194 candidate findings across 13 subsystems. The
adversarial verification pass did not complete, so everything below is a **lead
requiring confirmation before any work is scheduled against it.** Recorded so
the analysis is not lost, not so it can be treated as fact.

Highest-value leads, by subsystem:

- **descrypt is not bitsliced**, costing ~400x per core against John's bitsliced DES
- **Dictionary, hybrid, combinator, markov and prince modes never reach the SIMD
  fast path** — an 8-worker dict run is reportedly slower than a 1-worker mask run
- **Markov mode enumerates zero candidates** when its keyspace exceeds int64
- **Dictionary attacks cannot be checkpointed**; `--session` is silently ignored for `-M dict`
- **Multi-hash cracks are buffered in memory** and written to the potfile only at the
  end, so Ctrl-C loses every crack
- **Potfile entries carry no hash-type tag**, so a cracked MD5 can answer a `--show`
  for NTLM with the wrong plaintext
- **`--gpu` silently ignores `-s/--salt`** and converts a failed dispatch into "not found"
- **`zip2smith`, `7z2smith` and `pdf2smith` produce unusable or false-positive records** —
  including a confirmed wrong password reported as Found
- **No format module interface**: a format's behavior is spread across ~10 hand-edited
  switch statements, so Hashsmith cannot take outside format contributions the way
  Hashcat (`module_00000.c`) and John (`fmt_main`) can
- **Zero fuzz targets** across ~100 hand-written binary record parsers
- **`yescrypt` is absent** — the default `/etc/shadow` scheme on Debian 12,
  Ubuntu 22.04+, Fedora 35+ and Kali
- **Codecs have no known-answer vectors at all**, against the project's own
  457/457 discipline for hashes
- **No recursive "magic" decode**, no chained pipeline syntax, no custom alphabets,
  no hex-dump output formats, no brotli/zstd/xz, no Punycode

---

## 5. Claims checked and found wrong

Recorded because a gap list that only grows is not being tested.

- **"`go test ./...` is RED at HEAD."** It passes. `EXIT=0`, all packages ok,
  `cmd/hashsmith` 44.4s, `internal/bcryptlane` 30.5s. `TestSpeedupOverXCrypto` is a
  load-sensitive timing ratio the project already documents as flaky; it did not
  fire here. Flaky is not red.
- **"Hashcat rule parity is overstated."** It holds. 30,000 rules of
  `rockyou-30000.rule` parse with zero failures.
- **"The GPU backend is a demo path not wired to real cracking."** Both backends
  build, self-test against the CPU across five algorithms, and generate candidates
  in-kernel. The problem is throughput and defaults, not wiring.

---

## 6. Roadmap

Ordered so that each phase makes the next one measurable, and so the early
phases produce wins a user can feel.

### Phase 0 — Stop corrupting the user's input `[S]` — **DONE** (8755a51)

Everything in §2.1. This is a few days of work that fixes defects in five
commands at once, and it is a prerequisite for trusting any later measurement.

- [x] Route all input through one explicit layer with a documented contract: no
      comma splitting unless the user opts in, no whitespace trimming, `--` to end
      flag parsing, `-` means stdin everywhere
- [x] Stop the normalizer rewriting the target when `-t` is explicit
- [x] Fix the two-byte loss on non-seekable wordlists
- [x] Send `crack` results to stdout; keep progress on stderr
- [x] Add `--version`, and per-command `--help`

**Acceptance:** all six defects in §2.1 have a regression test; the argv and file
paths of the §1 harness produce byte-identical results; `crack ... | head` works.

### Phase 1 — Make the self-test measure the right boundary `[M]` — **DONE** (c5749dd, 36ada2d)

- [x] Add a CLI-level conformance harness that drives `hashcat --example-hashes`
      end-to-end through the real binary and records CRACKED / REJECTED /
      NO-SUCH-MODE / NOT-FOUND per mode
- [x] Commit the baseline (418/538 corrected) and fail CI on regression
- [ ] Add the equivalent for `john --list=formats`

**Acceptance:** `make conformance` prints the §1 table; CI fails if CRACKED drops.

### Phase 2 — Burn down the Hashcat record gap `[L]` — **IN PROGRESS**

With Phase 1 as the scoreboard, in strict value order:

- [x] The 7 silent NOT-FOUNDs — all fixed (§1.2) — wrong answers are worse than missing ones
- [x] LUKS v1 parser — **12 modes**, the single biggest rejection cluster
- [x] Every rejection closed: Episerver, MongoDB SCRAM, Oracle 11g, Juniper,
      AxCrypt 1, Werkzeug, PostgreSQL, Skip32, NetNTLMv2-NT, SNMPv3, Ansible,
      Bitwarden, Blockchain, NSEC3, RAR5, iTunes
- [ ] The 83 unimplemented modes, prioritised by engagement frequency. The
      largest coherent families are PKZIP/SecureZIP (10), Lotus Domino (3),
      DPAPI masterkey (4), MS Office <= 2003 (4), Electrum (2), AxCrypt 2 (2),
      Telegram (2), Mozilla key3/key4 (2), DiskCryptor (3), ENCsecurity (4)
- [ ] Raise the pinned baseline with each landing, never to silence a failure

**Acceptance:** CRACKED >= 500/538 (93%). State the residue and why.

### Phase 3 — Ship something a stranger can install `[M]` — **DONE** (fa731b4, 0a3f730)

Nothing above reaches a user while every install path is broken or stale.

- [x] Fix `setup.cfg` `package_data` and `MANIFEST.in`
- [x] Release workflow producing static binaries for linux/darwin × amd64/arm64
      and windows/amd64, plus GPU-enabled macOS builds
- [x] npm and Homebrew consume the release binaries instead of building from source
- [x] Dockerfile, shell completions, `--version` wired to the tag

**Acceptance:** on a clean machine with no Go toolchain, all three install paths
yield a binary whose `--version` matches the current tag.

### Phase 4 — Candidate quality `[M]` — **MOSTLY DONE** (44116fd, b89036d)

- [~] Not replaced. Discovery now finds the real lists john and hashcat ship,
      which covers the machines this tool actually runs on; the embedded
      fallback is still an English dictionary
- [x] Ship rule files, and `--rules` names resolve without a path
- [~] John's dialect reads 30.6% of its corpus, up from ~2%, and matches
      john candidate-for-candidate on its flagship Wordlist ruleset
- [x] Auto-discovery finds wordlists where john and hashcat install them

**Acceptance:** John's `[List.Rules:Wordlist]` loads at ≥ 95%; the default
wordlist cracks a representative leaked-hash sample at a rate comparable to
rockyou's first 250k lines.

### Phase 5 — Extractors `[L]` — **STARTED** (e3477d6)

The 62 in §2.6, ordered by how often an engagement produces that file:
Kerberos (`krb`/`kirbi`/`ccache`) → `pcap`/`wpapcap` → `putty`/`openssl`/`pem` →
Java `keystore`/`bks` → `DPAPImk` → wallets and password managers.

- [x] The round-trip test now exists, and it runs BOTH halves: crack with the
      right password, and assert a wrong one is rejected

**Acceptance:** every extractor round-trips a real file in CI; parity with John
on the Kerberos, capture and key families.

### Phase 6 — The GPU decision `[XL, or drop]` — **RESOLVED** (a42697f)

§3.2 is the evidence. Hashsmith's GPU buys 1.6x over its own CPU while Hashcat's
buys 17x. Three honest options:

1. **Drop it.** Remove the tags, delete the CI job, document CPU-only. Cheapest,
   and defensible given §3.1 shows Hashsmith already beats John on CPU.
2. **Fix the defaults only `[S]`.** Make `-tags opencl` the macOS default (1.43x
   free), fix the `--gpu` salt and error-swallowing leads, ship GPU binaries.
3. **Compete `[XL]`.** Autotuning, workload profiles, on-device rules, per-mode
   kernels. This is the decade of work the 2026-08-31 design doc already declined.

**Recommendation: option 2, then hold.** The 2026-08-31 spec ruled out competing
on GPU throughput and that call still looks right. But the backends now exist and
work; leaving the faster one unselected and unshipped wastes work already done.

### Phase 7 — Win where neither competitor is trying `[M-L]` — **STARTED** (d2947ca, 6ca46a5)

This is where "best encoding/decoding toolkit" is actually earned. Phase 0 fixes
six of this area's blockers for free; the rest is additive.

- [x] A round-trip property test over every codec, and six fuzz targets over
      the verifiers, identification, decoders, magic, rules and the input layer
- [x] Recursive magic decode — and it hands off to the identification engine
- [x] Chained pipeline syntax so a recipe is one invocation
- [ ] Custom alphabets for every base-N codec; the internals are already parameterised
- [ ] Hex-dump output formats, brotli/zstd/xz/bzip2, Punycode/IDNA, the missing
      classical ciphers
- [ ] An importable Go library API, so Hashsmith is embeddable rather than CLI-only

**Acceptance:** codec vectors reach parity with hash vectors; magic decode
resolves a 3-layer nested payload unaided.

---

## 7. What this roadmap deliberately does not do

- **It does not chase Hashcat's GPU throughput.** §3.2 measures the gap at 10.8x
  on identical hardware against a decade of per-mode kernel work. The 2026-08-31
  spec already declined this and the measurement supports that decision.
- **It does not chase John's 349-format count directly.** Format count is the
  wrong target; §1 shows reachability is the real gap. Phase 2 and Phase 5 raise
  reachability, and the count follows.
- **It does not add new formats before Phase 2 closes.** Adding to a registry
  where 23% of existing modes refuse their canonical record makes the headline
  number worse, not better.
- **It does not refactor to a module architecture yet.** That lead (§4) is real
  and probably right, but it is an XL change that would stall every phase above
  it. Revisit after Phase 3 ships.

---

## 8. Progress log

| Commit | Change | CRACKED / 538 |
|---|---|---|
| — | Baseline, corrected corpus | 418 (77.7%) |
| 8755a51 | Phase 0: input pipeline | 418 |
| c5749dd, 36ada2d | Phase 1: conformance ratchet | 418 |
| 6178bcb | hashcat LUKS v1 record (12 modes) | 430 |
| e86b1ed | 7 record-dialect fixes | 438 |
| 1a94db8 | Skype and MSSQL 2000 implemented | 439 |
| fa731b4 | Phase 3: packaging blockers | 439 |
| 03d9118 | Every remaining silently-wrong format | 444 |
| aa4ecd2 | Candidate-shape guards, PostgreSQL, Werkzeug | 449 |
| 5ba8465 | Ansible, Bitwarden, Blockchain record shapes | 452 |
| ed5a332 | NSEC3, RAR5, iTunes | **455 (84.6%)** |
| fa731b4, 0a3f730 | Phase 3: packaging, release, Docker, completions | 455 |
| 44116fd | Phase 4: wordlist discovery, bundled rulesets | 455 |
| b89036d | Phase 4: John's rule dialect | 455 |

Figures include the 13-14 VeraCrypt modes the harness classifies TIMEOUT under
its 20-second bound, which crack when unbounded.

### Where the residue now is

| Outcome | Modes |
|---|---|
| CRACKED (incl. TIMEOUT) | 455 |
| **NO-SUCH-MODE** | **83** |
| REJECTED | **0** |
| NOT-FOUND | **0** |

Both failure classes that represent *defects* are closed. Every mode Hashsmith
claims to support accepts hashcat's own canonical record and recovers the
password hashcat states is correct. What is left is not a defect list — it is
83 formats that have never been implemented.

### What the burn-down actually found

The interesting result is not the number. It is that **five self-test vectors
were agreeing with bugs.** Each was produced by Hashsmith against its own
derivation, so it could only ever confirm that the code still did what it had
always done:

| Format | What the vector pinned |
|---|---|
| `rar5` | Bytes 32..40 of a 40-byte PBKDF2, instead of RAR5's snapshot-and-fold. No RAR5 password could ever have verified. |
| `mssql2000` | An unsalted SHA-1 that is not MSSQL 2000 at all |
| `azuresync` | The raw NT hash as the PBKDF2 password, not its uppercase hex in UTF-16LE |
| `ansible` | A field order neither john nor hashcat emits |
| `sha256-salt-utf16lepass` (as -m 13800) | Salt-first, where Windows Phone 8+ appends it |

All five are now hashcat's published records with `srcPublished` provenance.
This is the strongest argument in the document for §6's Phase 1: a self-test
built from your own output measures self-consistency, not correctness, and it
stays green through exactly the bugs it exists to catch.

### BSDi extended DES crypt, and a vector that could not catch the bug

`-m 12400` is implemented. It extends traditional DES crypt three ways, and all
three matter to a verifier: the iteration count is per hash instead of fixed at
25, the salt is 24 bits instead of 12, and a password longer than eight
characters contributes ALL of itself rather than being truncated.

That last one is where this went wrong, twice. Hashcat's published vector uses
the password "hashcat" — seven characters — so it never enters the folding loop
at all, and two different readings of that loop reproduced the vector exactly.
The fix was to generate records here for longer passwords and hand them to
**john**, which cracked "hashcat" and "abcdefgh" and refused every longer one:
the precise signature of a correct first block and a wrong fold. The right
answer is that the key is encrypted UNDER ITSELF and the next eight characters
XORed into the result.

John then cracked all six, including a 20-character password and one with
spaces, and those records are now vectors — evidence about the format rather
than a transcript of this implementation. The tests also check that a password
truncated to eight characters does NOT verify, which is the classic way to get
this wrong, and that two records with different iteration counts produce
different answers, which a verifier hard-coding descrypt's 25 rounds would fail.

### GOST R 34.11-94, where fetching the specification was the whole job

`-m 6900` is implemented, and the route there is the point. Two reconstructions
from memory produced self-consistent digests that matched nothing. Fetching
RFC 5831 settled it in one step: the transposition P, the shift A, the mixing
psi and the round structure were already right, and exactly one thing was
wrong — the constant C3, which the RFC spells out as a bit pattern and which I
had guessed at two words of.

Fixing the constant exposed a second bug, of a completely different kind. The
S-box tables fold the cipher's 11-bit rotation in at build time, and for the
top table the shift is 11 + 24 = 35. **In Go a `uint32` shifted by 35 is
zero**, so a quarter of the substitution silently vanished and every digest was
wrong in a way no amount of reading the specification would have explained. One
`% 32` fixed it.

Then the published vectors landed exactly: `""` gives
`ce85b99c…` under the standard's test parameters and `981e5f3c…` under
CryptoPro's, both matching the values in circulation.

**And that pair turned out to be the format's identity, not a footnote.** The
standard does NOT fix the S-box. Hashcat's own example settles which one mode
6900 means: "hashcat" hashes to `df226c2c…` under the test parameters and
`256f021a…` under CryptoPro. Both are implemented — `gost` for hashcat's, and
`gost-cryptopro` for what a Russian PKI deployment means by the same name —
because a bare 64-character digest cannot say which it is, and offering only
one would miss half the format. Auto-detection proposes both, which is the same
treatment Streebog already gets in that family.

### An extractor where the verifier was already the hard half

`ecryptfs2smith` reads a wrapped-passphrase file, which is the container behind
the `-m 12200` records implemented earlier. Two shapes, told apart by the first
two bytes: version 2 carries its own eight-byte salt, version 1 does not and
gets it from the user's `.ecryptfsrc`.

It agrees with `ecryptfs2john` on version 2 byte for byte, and on version 1 it
does slightly better: john takes the `.ecryptfsrc` as a second argument and
emits the unsalted record when you forget, while Hashsmith finds it.

Finding it is also where the bug was. The first version looked one directory up
unconditionally, so a wrapped-passphrase copied anywhere under a home directory
picked up that home's salt — producing a record that looks MORE precise than
the short one and cannot crack. The parent is now consulted only when the file
sits in a directory named `.ecryptfs`, which is the layout eCryptfs actually
creates, and a test extracts from a copy in a sibling directory to watch the
salt NOT follow it.

### An extractor that paired fields from different key bags

Surveying john's extractors for ones whose record Hashsmith already verifies
turned up `itunes_backup2john` — and the survey was wrong, because Hashsmith
has had an iTunes extractor all along under a different name. Reading john's
version beside it found a bug anyway.

An iTunes backup key bag holds SEVERAL tag groups, one per protection class.
Hashsmith took the first `SALT`, the first `ITER` and the first `WPKY` found
anywhere in the file, which draws them from different groups whenever an
unrelated `WPKY` comes first — a legal layout. The result is a record that is
perfectly well formed and cannot crack: the salt and iteration count are the
backup's, the wrapped key is something else's, and a user runs a full attack
and gets "not found" for the correct password.

Demonstrated before fixing, with a key bag built around hashcat's own published
example: the extractor produced a record whose wrapped key was the decoy's, and
the known-correct password did not verify against it. The three tags are now
required in order and within a bounded distance, which is the constraint
itunes_backup2john applies and for the same reason, and the test keeps a
decoy group in front to hold it.

### A mode NOT implemented, three attempts over

ODF (`-m 18400` and `-m 18600`) was attempted three times and abandoned, on the
same principle as MultiBit. The record is fully parameterised — cipher,
checksum, iterations, key size, salt, IV — and no reading reproduces either
vector.

What is now established rather than assumed. John parses hashcat's record and
cracks it, reporting `PBKDF2-SHA1 … BF/AES`, so the field reading here is
right and the PRF is SHA-1. The OASIS specification says the cipher is Blowfish
in **8-bit** CFB with an 8-byte IV, and that the checksum applies SHA-1 to the
first 1024 bytes of the *compressed unencrypted* file — so over decrypted bytes
that are still DEFLATE-compressed, which is what was assumed.

Ruled out against both published vectors: start key SHA-1 and SHA-256, PBKDF2
PRF SHA-1 and SHA-256, key length 16, 20 and 32, Blowfish in CFB-64, CFB-8 and
CBC, AES-256-CBC, the IV and salt fields in both orders, and the checksum over
the full plaintext and over its first 1024 bytes. None of the resulting
plaintexts looks like a DEFLATE stream, which says the key derivation is wrong
rather than the cipher framing — and the specification's own wording did not
close the gap.

Shipping the most plausible reading would have produced a verifier that parses
every record and rejects every password. Two modes left honestly unsupported
beat two that claim support and waste a run.

### Android Backup, where the check was stronger than it needed to be

`-m 18900` now cracks, and nothing about the cryptography changed. The
verifier decrypted hashcat's record correctly all along and then rejected it on
a structural check that was never the source of its strength.

Android's master-key envelope is a fixed 83 bytes — a 16-byte IV, a 32-byte
master key and a 32-byte checksum, each behind a length byte — so a 96-byte
blob always unpads to exactly 83 with thirteen bytes of `0x0d`. The verifier
additionally demanded the three length tags read 16, 32 and 32. That is true of
the records `androidbackup2john` writes and NOT of hashcat's example, which
carries its envelope differently.

What settled it was noticing that hashcat's blob decrypts to **clean padding**
under the same key derivation. A wrong password decrypts to noise, and noise
ends in thirteen bytes of `0x0d` with probability 2^-104 — so the password was
already proven right, and the tag check was rejecting a record it had no
business rejecting. The check is now the envelope LENGTH, which carries that
same 2^-104 and no longer encodes one tool's framing. Measured over 4,158 wrong
passwords: none accepted.

The lesson is narrower than "checks should be loose". The tags added nothing on
top of 2^-104; they were pure format assumption wearing the clothes of rigour.

### CORRECTED: the VeraCrypt timeouts are MARGINAL, not inherent

An earlier version of this section concluded that all fourteen timing-out modes
were "correct and slow, not broken", on the strength of a cost measurement and
some arithmetic. Both were taken on the contaminated machine described in the
correction above, and both were wrong by about a factor of two.

Re-measured on a quiet machine, PBKDF2 at 20,000 iterations:

| PRF | contaminated | clean |
|---|---|---|
| SHA-256 | 9.7 ms | 7 ms |
| SHA-512 | 13.6 ms | 9 ms |
| RIPEMD-160 | 178.6 ms | 111 ms |
| Whirlpool | 180.4 ms | 106 ms |
| Streebog-512 | 385.4 ms | 215 ms |

The RATIOS survive — Streebog is still ~24x SHA-512, and the reason is still
that SHA-512 has a Go assembly implementation while the others are pure Go —
so "the gap is the hash, not the HMAC wrapper" stands. What does not survive is
the conclusion.

At 215 ms per 20,000 iterations, VeraCrypt's 500,000 come to about **5.4
seconds per candidate**, not the 23 seconds computed from the inflated figures.
The conformance harness gives each mode 20 seconds and four candidates, so
these modes land at roughly 21 seconds against a 20-second budget: **right on
the line, not far past it.**

And they behave like it. A read-only run on the clean machine reported 456
cracked and 12 timeouts; the regeneration a minute later reported 455 and 13.
One mode — `-m 29481`, VeraCrypt Streebog-512 + XTS 512 with boot mode — moved
from TIMEOUT to CRACKED and is now pinned there.

So the honest statement is that these modes are MARGINAL on this machine rather
than out of reach, they will flicker with load and hardware, and the
keep-CRACKED rule added earlier is doing exactly the job it was written for:
once a mode is pinned CRACKED, a later timeout cannot silently unpin it.

Conformance on a quiet machine: **455 of 538 (84.6%)**, with 13 timeouts.

### Still open

- **83 unimplemented modes.** Largest coherent families: PKZIP/SecureZIP (10),
  DPAPI masterkey (4), MS Office <= 2003 (4), ENCsecurity (4), Lotus Domino (3),
  DiskCryptor (3), Android FDE (3), legacy PDF (3), Electrum (2), AxCrypt 2 (2),
  Telegram (2), Mozilla key3/key4 (2).
- **Phase 3 remainder**: release binaries, Docker, shell completions, and
  switching Homebrew and npm to prebuilt artifacts.
- **Phases 4-7**: wordlists and rule files, extractors, the GPU decision, and
  the encoding/decoding work. Untouched.

### Verified at ed5a332

`go build ./...`, `go vet ./...`, and `go test ./...` all clean. Both GPU build
tags compile. All four cross-compile targets build. `selftest -slow` passes with
461 of 461 crackable formats carrying a vector. The pip wheel unpacks to a Go
tree that compiles.

### Phase 3 and 4, what landed

**Distribution.** A release workflow builds static CGO_ENABLED=0 binaries for
five platform pairs plus separate Metal and OpenCL macOS builds, checksums them
into the GitHub Release, and refuses to ship a binary that cannot pass its own
known-answer vectors. A scratch-based Docker image carries one 14 MB static
binary. npm downloads the release binary and verifies it against SHA256SUMS
before running it, falling back to a source build; `npm install
--ignore-scripts`, which used to leave the command permanently broken, now just
defers the work to first run. A Homebrew formula installs a prebuilt binary and
its test block runs the binary's own vectors rather than checking it starts.
`hashsmith completion bash|zsh|fish` generates from the live registries, so a
format added tomorrow completes without anyone editing a script.

**Candidates.** Wordlist discovery was two filenames, rockyou.txt and
rockyou.txt.gz. The people who run this tool usually have john or hashcat
installed and both ship a real password list; neither was ever found. Discovery
is now tiered — the file decides first, the directory decides among equals —
and on this machine that is the difference between falling back to an
alphabetical English dictionary and using john's 3,546-entry password.lst.
Four rulesets are authored and embedded, resolvable by bare name.

**John's rule dialect.** The engine was Hashcat-complete and could read
essentially no John ruleset. It now reads 30.6% of John's 614-line corpus and
reproduces john's candidate stream exactly on its flagship Wordlist ruleset.
All 28 stock hashcat rule files are byte-identical before and after.

Two claims in §4 were checked against the binaries and found **wrong**:

- `M`, `Q`, `(`, `)` and `%NX` were listed as hashcat operators Hashsmith
  lacked. hashcat v7.1.2 answers "No valid rules left." for a `-r` file
  containing any of them. They are documented but not accepted, so they are
  John-only here.
- The dialect cannot be detected from marker syntax. `-8` is a valid hashcat
  rule and a valid John flag; `@?d` means different things in each. Two
  heuristics each read a real hashcat file as John and silently dropped every
  candidate. The dialect is chosen by compiling both ways instead.

### Still open

- 83 unimplemented hashcat modes.
- 69% of John's rule corpus, dominated by its `a` command (262 lines).
- The embedded fallback wordlist is still an English dictionary.
- Phases 5, 6 and 7: the 62 missing extractors, the GPU decision, and the
  encoding/decoding work.

### Phase 6 and 7, what landed

**The GPU decision resolved as option 2, plus two correctness fixes that turned
out to matter more than the performance question.** `--gpu` with a salt hashed
the bare candidate and reported "Not found" for a password the CPU path
recovers in the same command; a failed kernel dispatch was converted into the
same answer. Both now decline the GPU and say why. On the backend question the
measurement corrects the gap report: on in-kernel brute — the cracking path —
OpenCL's median exceeds Metal's best over six runs each, but the factor is
nearer 1.5x than the reported 1.8x, and on bulk dispatch Metal is slightly
ahead. The build tags are left alone; the release workflow ships both.

**Codecs now meet the standard hashes are held to.** A round-trip property test
over all 60 entries, with payloads chosen to be the shapes that broke in
practice, found four defects at once: Ascii85 silently dropped the final
partial group so "hello" decoded to "hell"; brainf*ck corrupted every non-ASCII
input; five catalogue entries were labels rather than usable `-t` names; and
file substitution was silent, so on a case-insensitive filesystem
`encode -t base85 Hashsmith` encoded a 20 MB binary instead of nine characters.

**`hashsmith magic`** peels encoding layers automatically and hands what it
finds to the identification engine, so a chain can end at "identified as:
bcrypt" rather than at bytes. Neither competitor has anything comparable.
`-t a+b` replays a chain in one invocation, mirroring magic's output.

### Fuzzing, and Phase 5's prerequisite

**231 verify\* functions across 70 files had no fuzz coverage**, and every one
of them parses data an attacker supplied. Six targets now cover them, seeded
from the hashcat conformance corpus so the fuzzer starts inside the field
parsing rather than at the "is this even a record" gate. The contract each
asserts is deliberately weak — never panic — because that is the one contract
that holds for every parser at once.

Two findings in the first two minutes. A three-character argument crashed the
process: in `<~>` the opening and closing Ascii85 delimiters are the same three
characters, so stripping two from each end asked for `value[2:1]`. And `magic`
inflated 64 MiB per search node to discard it, because the ceiling that bounds
decompression work is the one on the RESULT — 180 MB of resident set down to
24 MB at the same wall clock. Everything else held: 2.8 million executions of
the verifier target across 37 formats each, about 104 million calls, no panic.

**Phase 5's prerequisite is done.** No test had ever taken a real container,
extracted from it, and cracked the result with the password the file was built
with — every extractor test used a hand-written fixture, which checks the
parser against what its author believed the format to be. The round trip now
runs both halves, the second being that a WRONG password is rejected, because
an extractor that drops an authentication tag reports a wrong password as
correct and a one-sided test would pass anyway.

ZipCrypto, WinZip AES, OpenSSH keys and PKCS#12 pass both halves. 7-Zip failed
both on every archive 7z writes, and was made to refuse rather than emit a
record that cannot crack — verification needs the decrypted payload's CRC and
unpacked size, which live inside a nested next-header the extractor did not
parse. Refusing was the larger feature: a user handed an uncrackable record
runs a long attack and concludes their wordlist is wrong.

### 7-Zip, closed

The next-header parser now exists, so 7-Zip gets the same round trip as every
other container and the refusal test is gone. The header is a nested,
self-describing structure of variable-length integers where every count read
from the file decides how many more reads follow, which is why every count is
read through a capped accessor and why the parser has its own fuzz target —
658,000 executions, clean.

Parsing it produced a finding that changed the design. A folder holding exactly
one file records that file's CRC in SubStreamsInfo, NOT in the folder, so the
two archives that looked CRC-less at the UnPackInfo level both had one. Picking
it up is the difference between a record that can prove a password right and
one that can only fail to prove it wrong.

Which check a record carries is a property of the archive:

| Archive | Chain | Record |
|---|---|---|
| `7z a -mhe=on` | AES alone | `$7z$0$…`, CRC-checked |
| `7z a -m0=Copy` | AES then Copy, the identity coder | `$7z$0$…`, CRC-checked |
| `7z a` (default) | AES then LZMA2 | padding-checked |

The first two are hashcat's own records, and `hashcat -m 11600` cracks the ones
Hashsmith writes — confirmed against v7.1.2, and pinned by a test that runs
hashcat, because Hashsmith cracking its own record proves only that its
extractor and verifier agree, which they would even if both were wrong.

The third cannot be. A compressing chain means the recorded CRC covers
DECOMPRESSED bytes, so checking it per candidate would mean running LZMA.
7-Zip zero-pads the AES stream to a block boundary instead, and those padding
bytes are a complete test on their own: a wrong key leaves each one random, so
even the four-byte minimum is one false positive in four billion. Hashcat's own
compressed form was tried against v7.1.2 across every field layout that would
load — data types 1, 2, 128, 129 and 130, both unpacked-size conventions, four
coder-attribute encodings — and none cracked, so Hashsmith writes its own
record and puts the padding length where hashcat keeps a codec id. A test pins
that hashcat REFUSES it: a wrong-but-loadable record would silently never
crack, which is the exact failure the refusal was built to prevent.

### CORRECTION: the timing-ratchet story below was wrong, and self-inflicted

**The two sections that follow are kept as written, and both are wrong about
the cause.** They are left in place because the reasoning in them is exactly
the reasoning that needs to be visible when it turns out to be mistaken.

While investigating the first bcrypt failure, a probe spawned eight infinite
busy-loop shells to simulate machine load. The cleanup `kill` did not reach
them — they were orphaned to init — and they ran for **four hours and
seventeen minutes**, saturating all eight cores of the measuring machine. Every
"under sustained load" reading in the next two sections came from that.

Measured after killing them:

| condition | speedup |
|---|---|
| quiet machine | 2.19x, 1.90x, 2.11x |
| WHILE a full `go test ./cmd/hashsmith` ran alongside | 1.89x, 2.12x, 2.14x |

All clear of the 1.63x floor. The reference side read 1.84ms against the 3.27ms
recorded during the contaminated period, and the full suite now takes 122
seconds where the "normal" baseline had been 180 — so even the runs treated as
clean were contaminated.

**What changed as a result.** The exclusivity gate is reverted: the ratchet runs
in the default suite again, where a ratchet belongs, because the premise that
it could not be measured there was false. What stayed is the part that was a
genuine improvement either way — the two sides are measured in alternation
rather than in separate blocks, and a reading below the floor is re-measured
before it fails. The same applies to the batch-feasibility retry: the fix is
sound and its sibling test already used that pattern, but the failure it was
written for was almost certainly the same eight processes.

The lesson is not about ratchets. A measurement that disagrees with every
expectation deserves a look at what else is running before it gets an
explanation — and a background process spawned by a probe is the experimenter's
responsibility to account for and to clean up.

### SECOND CORRECTION: the correction above also blamed the wrong thing

The section immediately above is right that eight runaway busy-loops
contaminated the original investigation. It is wrong about what that implied,
and one sentence in it is a straightforwardly false measurement claim:

> The reference side read 1.84ms against the 3.27ms recorded during the
> contaminated period, and the full suite now takes 122 seconds where the
> "normal" baseline had been 180 — so even the runs treated as clean were
> contaminated.

Four consecutive runs of the package on its own, on a genuinely quiet machine
(load average 2.0, nothing else running), read:

| | reference (x/crypto) | lane, per candidate | speedup |
|---|---|---|---|
| run 1 | 3.259 ms | 1.5266 ms | 2.13x |
| run 2 | 3.264 ms | 1.5265 ms | 2.14x |
| run 3 | 3.265 ms | 1.5264 ms | 2.14x |
| run 4 | 3.254 ms | 1.5268 ms | 2.13x |

The quiet reference is **3.26 ms**, not 1.84 ms — which also means the
`refQuietBaselineNs = 3.3e6` constant was right all along, and the claim that
the machine "had been running at roughly half speed" was invented to explain a
number that never existed in the quiet condition. The 1.84–2.41 ms readings
that produced it were taken *while a concurrent suite ran*, and were therefore
FASTER under load than at rest. That inversion is real and reproducible on this
hardware; the likely cause is macOS placing an otherwise-idle single-threaded
benchmark on an efficiency core and promoting it to a performance core once the
machine is busy, but that is a hypothesis and has not been tested, so nothing
here depends on it.

**The reverted gate was also wrong.** On a demonstrably clean machine, the
ratchet still failed **2 runs out of 4** under `go test ./...`, at 1.57x and
1.61x, while passing every single time the package ran alone. So the original
complaint was not purely an artefact of the runaway processes; it had a real
component underneath.

**What the real mechanism turned out to be.** In the failing `go test ./...`
run, the reference side read 3.255 ms — indistinguishable from its 3.259 ms
quiet reading — while the lane side read 2.075 ms/candidate against 1.527 ms
quiet. The contention landed almost entirely on one side of the ratio. One
bcrypt state is a single ~4 KB Blowfish S-box set; four interleaved lanes are
four of them, so a sibling test binary evicting cache hits the lane side and
largely misses the reference.

That is fatal to the load guard as it was written. A guard watching the
reference side's absolute cost sees a perfectly healthy machine in exactly the
case it exists to catch — and no amount of adjusting its threshold changes
that, because the quantity it watches does not move.

**The fix: let the measurement judge its own samples.** Contention is bursty
where a real regression is not, so dispersion across repeated samples of the
same work separates the two cases cleanly. The statistic is median/min rather
than max/min, because the result is a best-of-N: it survives one unlucky sample
intact, and is invalidated only when MOST samples are dirty, which is precisely
what median/min measures. Five interleaved samples per side, same machine, same
day:

| | max/min | median/min |
|---|---|---|
| quiet, lane | 1.001, 1.001, 1.001 | 1.0005, 1.0006, 1.0004 |
| quiet, reference | 1.002, 1.013, 1.002 | 1.0009, 1.0007, 1.0007 |
| contended, lane | 1.091, 1.231, 1.238 | 1.0485, 1.0947, 1.1541 |
| contended, reference | 1.085, 1.168, 1.274 | 1.0677, 1.0636, 1.2151 |

max/min was tried first and rejected on evidence: a single hiccup on an
otherwise quiet machine pushed it to 1.047 against a 1.05 ceiling, while the
same samples read 1.001 by median/min. The ceiling is set at **1.02** — twenty
times above the quiet cluster, below half the contended one. Unlike
`refQuietBaselineNs` it is not a hardware constant but a self-consistency check
on the measurement, so it carries to other runners unchanged.

**And a skip must not become a silent hole.** The obvious failure mode of "skip
when you cannot measure" is a ratchet that quietly stops ratcheting. So
`HASHSMITH_RATCHET_REQUIRED=1` turns every skip in that test into a failure —
the `-short` skip included, since a required measurement a flag can switch off
is not required — and a dedicated `bcrypt-ratchet` CI job sets it and runs the
package on its own, retrying up to three times so a noisy shared runner costs a
retry rather than a red light.

Three things about this episode are worth keeping. The correction above reached
for one cause that explained most of the evidence and stopped there, when the
evidence had two causes in it. It asserted a specific measurement (1.84 ms)
that no one had taken in the condition claimed. And the guard it left in place
was watching the one quantity that provably could not see the problem — which
only became visible by logging the two sides separately instead of the ratio
they produce.


### A timing ratchet that could not be measured where it ran

The bcrypt speedup ratchet failed at 1.10x during a full-suite run, with its
reference side measuring 3.27ms — its normal quiet-machine cost, so the
existing load guard saw nothing wrong. The two sides do not degrade together:
under load the four-lane side ran at 2.59ms per candidate against a quiet 1.72,
while the single-lane reference sat at its quiet value, so the ratio collapsed
with nothing actually slower.

Interleaving the samples was the first fix and is a real improvement — the two
sides now alternate, so bursty load hits both — but it does not save a
sustained case, and a rerun under sustained load still read 1.29x. Two probes
were then tried and neither separates load from a regression. A cache-footprint
probe cannot see the pressure: an M2 performance core has 128 KiB of L1 data
cache, so four Blowfish S-box sets are nowhere near it, and the probe read
between 1.00 and 1.35 on an idle machine. A parallel-efficiency probe reads
about 1.0 loaded and quiet alike, because the single-goroutine baseline it
divides by degrades along with everything else. Guarding on the lane side's own
absolute cost fails worse: at the multiplier needed to catch the 1.5x inflation
seen under load, a genuine 1.5x regression would skip instead of fail.

So the requirement is exclusivity, stated rather than inferred.
`HASHSMITH_TIMING_RATCHET` gates the test the way `HASHSMITH_REQUIRE_AVX2`
already gates the AVX2 cores, the skip says in as many words that the floor was
NOT checked on that run, and CI measures it in the bench job, which has its
runner to itself.

The recorded failure is worth keeping in view: a ratchet that flakes gets
lowered, and a floor lowered to silence a measurement artefact is a floor that
no longer ratchets anything.

**A second throughput ratchet had the same defect**, found by the same
full-suite run that confirmed the first fix. `TestBatchFeasibilityProbeBeats­ScalarPath`
compares the batch dispatch path against the scalar verify closure and read
0.93x against a 1.20x floor, with nothing slower — it passed three times in a
row when run alone.

The test already skipped itself under binary translation and under the race
detector, both for the same stated reason: the comparison is only meaningful
when its overhead falls evenly across the two paths. A machine doing something
else is a third way for that to stop being true, and it was not covered. Both
probes run four goroutines, but the dispatch path also coordinates a batch, so
contention costs it more.

The fix is the retry-and-keep-the-best loop its own sibling test in the same
file already used, which is a better answer here than the exclusivity gate:
it keeps the test running everywhere, and it keeps the mutation check the test
doubles as. A dispatch path that is genuinely slower than the scalar closure is
slower on every attempt, so nothing is hidden.

### The fallback wordlist was long, not useful

The embedded `common.txt` is what a run uses on any machine without a
rockyou.txt, which is most machines that are not Kali. Its value is not its
length — it is that the likeliest candidates come first, because an
interrupted run, or one attacking a slow KDF, only ever reaches the beginning
of it.

That property was absent and nothing had checked for it. Of the 3,545 entries
in John's default `password.lst`, the 230,930-line list contained 1,839
anywhere at all and **91 within its first 5,000 lines**. A Hashsmith run that
tried 5,000 candidates from its own default was trying 91 real passwords;
John's default would have tried 3,545. The list was 111 curated passwords
followed by an alphabetical English dictionary — 145,455 consecutive entries
in sorted order.

`password.lst` is merged in as the frequency data the list was missing. Its
author states in its header that it is assumed to be in the public domain, and
it is ordered by decreasing frequency. The two orderings combine by reciprocal
rank fusion, the ordinary way to merge ranked lists that share no scale: near
the top of either rises, near the top of both rises further, and neither
ordering is destroyed. The head is now 3,583 frequency-ordered passwords; the
dictionary stays, demoted below everything carrying a frequency signal,
because dictionary words are genuinely used as passwords.

The coverage figure after the merge is 100% by construction and is not the
claim. The claim is the structural one: the list now has a frequency-ordered
head, and three tests hold it there. One measures the longest alphabetically
sorted run in the head, with the bar set from two measurements rather than
taste — the defect ran 63% of the file sorted, while John's own list contains
a deliberate 782-entry sorted block, so a strict bar would fail a canonical
hand-curated list.

`wordlists/common.txt` at the repo root is a second copy that nothing reads.
It is kept in sync here, but it can drift silently and is worth either wiring
up or deleting.

### John's rule dialect, measured against John instead of against its manual

The corpus figure was re-measured properly first, because the old one counted
`.include` directives and blank lines as rules. Of **251 real rule lines** in
john.conf, 168 compiled — **66.9%**. The failures were not one missing feature
but nine, and naming them took reading john's `RULES` rather than guessing from
the error text.

What landed: `aN`/`bN` (early rejection on length), `S` (shift case by
keyboard), `R`/`L` (shift every character one key right or left), `V` (lowercase
vowels, uppercase consonants), `WN` (shift-toggle one character), `=NX` and
`=N?C` (reject unless the character at N matches). Coverage is now **82.5%**,
held by a ratchet.

`R` and `L` were not missing so much as wrong. Hashcat spells the same letters
`RN` and `LN` and means a bitwise shift of one character, taking an operand
John's forms do not — so `l Q [RL]` in john.conf failed to compile, and where a
command followed, it would have been eaten as a position and the rule would
have run as something nobody wrote.

**Then the differential test found four bugs the manual would never have
shown.** Running john and comparing candidate streams, rather than comparing
against a golden file captured from a previous reading of the docs:

- `WN` is not a case toggle. It is a SHIFT toggle, so `W1` turns `P@ssw0rd!`
  into `P2ssw0rd!` where a case toggle returns the word unchanged.
- `p`, `P` and `I` are **case-sensitive**, which john's docs say in three words
  — "(lowercase only)". Hashsmith lowercased before testing the suffix, so
  every capitalised word ending in y, f, fe, s, x, z, ch or sh got a different
  candidate. `WIFE` pluralises to `WIFEs`, not `WIVes`. Those are exactly the
  words a ruleset reaches after a `c` or a `u`.
- The grammar commands have length guards and skip conditions: `p` leaves a
  one-character word alone, `P` and `I` leave anything under three, `P` skips a
  word already ending in `ed` and doubles a trailing b, g or p (`walking` ->
  `walkingged`), and `I` skips one already ending in `ing`.
- A backslash escape resolved only when an unrelated bracket group appeared
  elsewhere on the same line. `[ab]\[` expanded correctly; `\[` alone did not,
  because the expander short-circuited on a line with no groups and returned it
  raw. john.conf's own `>9 \[` hit exactly that.

None of these were visible from the rule files, the documentation, or the
existing golden-file test, which recorded what Hashsmith believed john does.
CI now installs john and runs the comparison, so the claim is checked rather
than asserted.

### The preprocessor, and a rule the documentation does not state

Coverage moved again, to **84.1%**, on three preprocessor features — and on a
fourth thing that was not missing but wrong.

`\0` through `\9` are BACK-REFERENCES to an earlier range. Unlike `\pN` they
carry no bracket and add no group: they emit whatever character the referenced
range is currently substituting. Hashsmith had no case for them, so they fell
through to "a backslash escapes the next character" and a digit was appended
literally — `$[12]$\0` produced `$1$0` and `$2$0` where john produces `$1$1`
and `$2$2`. `\p0` was the same story, expanding to a literal `p0` and
multiplying a range that should not have multiplied.

The fourth is the interesting one. **John's ranges collapse duplicates**, which
its documentation mentions once in passing — `[aeioua-z]` is "vowels followed
by all other letters" and the preprocessor "is smart enough not to produce
duplicate rules". Hashsmith expanded ranges literally, so `[aabbcc]` became six
rules where john makes three, and every such range produced duplicate
candidates for the whole run.

The `\r` escape turns that off, and what it actually does had to be measured,
because the documentation describes it only in terms of parallel ranges:

| range | plain | with `\r` |
|---|---|---|
| `[abca]` | abc | abca |
| `[a-ca-c]` | abc | abcabc |
| `[aab]` | ab | ab |
| `[1-9A-ZZ]` | 35 chars | 35 chars |

The last two are the tell: **adjacent duplicates collapse whether or not `\r`
is present**, and `\r` suppresses only the global pass. john.conf's own
`->\r[1-9A-ZZ]` is that fourth row, so reading `\r` as "keep everything"
would have given it 36 branches against john's 35 — a difference of one
candidate, in a line that looks like it was written to test exactly this.

The live differential now runs 83 rules through john and compares streams,
including every case in that table.

### A character class that was a reasonable reading and still wrong

Adding `s?CY` — substitute every character of a CLASS — immediately found a
bug in the class table itself. `?s` was implemented as "printable, not a
letter, not a digit", which is what the word "symbols" suggests. John's `?s` is
an explicit 23-character set, and the nine characters of `?p` are PUNCTUATION
and deliberately outside it. So `s?s_` on `P@ssw0rd!` gave `P_ssw0rd_` here
against john's `P_ssw0rd!`.

The class form was not merely missing, either. Without it `s?D*` read `?` as
the character to replace and `D` as its replacement, then met `*` as a command
and failed loudly — but a rule whose next character happened to be a valid
command, `s?dl` say, would have compiled SILENTLY as "replace ? with d, then
lowercase". Wrong candidates, no error.

`?o`, `?y`, `?b` and `??` were missing outright. The whole table is now read
out of john one byte at a time: substitute a marker for every member of a class
over a word containing every printable byte, and compare the sets. All fifteen
classes match. That comparison is a test, because a spot check is exactly what
let `?s` stay wrong — no rule in the test list happened to use it on a `!`.

Corpus coverage: **84.9%**.

### `XNMI`, and an operand that must not be clamped

John's memory-substring command takes up to M characters of the MEMORISED word
starting at N and inserts them into the current word at I. Every one of john's
documented examples now matches: `X011` duplicates the first character, `Xm1z`
the last, `dX0zz` triplicates the word, and `X0z0` — the form john.conf uses six
times — prefixes the word with its memorised self.

`dX0zz` is the one worth having in the test list. It gives THREE copies, not
four, because the memory holds the word as it was before `d` doubled it. An
implementation that memorised lazily, or that read the current word instead,
passes every other example here and fails that one.

The operands deliberately do not go through the shared position parser. That
parser clamps a position character it does not recognise to the maximum length,
which is correct for a length and silently wrong for a START: `Xp…` would
become "start past the end", extract nothing, and leave the word unchanged with
no indication at all. John's `p` is the position of the last character found by
`/` or `%`, which Hashsmith does not track, so `X` refuses it and says so.
john.conf's two `Xpz0` lines stay unsupported and now explain themselves
instead of compiling into a no-op.

Corpus coverage: **87.3%**.

### Numeric variables, and the position that makes them useful

`vVNM` sets variable V to N minus M, over eleven variables `a` through `k`.
On its own it is nearly pointless: john.conf's seventeen lines that use it all
read `p` — the position matched by the LAST `/` or `%` — and `p` was the piece
Hashsmith did not have.

What `p` points at had to be measured, and `Dp` is the probe that shows it:

| rule | on "one two three four five" |
|---|---|
| `/[ ] Dp` | deletes the FIRST space |
| `%2[ ] Dp` | deletes the SECOND |
| `%4[ ] Dp` | deletes the FOURTH |

So `%N` records the Nth match, not the first. That is the whole point of
john.conf's `%4[ ] … va01 vbpa Tb`: set `a` to -1, set `b` to `p`+1, toggle
there — capitalise the word after the fourth space. Recording the first match
would have capitalised the wrong word, quietly, in a ruleset whose output
nobody diffs.

The implementation stays off the hot path. A command with constant operands
compiles to the same closure it always did; only a rule that actually writes a
variable or `p` takes the slower route, through a side map like the one memory
and the memory-substring command already use. `/` and `%` record their match
position in John's dialect only, because hashcat has no `p` and should not pay
for one.

Corpus coverage: **94.8%**, and the live differential now runs 105 rules
through john.

### Nine rules that were never broken, and four that cannot be read

The last two buckets turned out not to be missing features at all.

**Nine lines carry John's `-p` flag**, which means "reject this rule unless
word-pair commands are allowed". Word pairs are a single-crack idea: the
candidate source there is a user's GECOS field, so a rule can act on the first
name, the second, or their concatenation. A wordlist run has no pairs, and john
skips every such rule — `-p 1 l` through `john --wordlist --stdout` prints
nothing, while the same rule WITHOUT the flag is a hard error there ("Unallowed
command"). Hashsmith stripped the flag and then reported the leftover `1` as an
unknown command, telling a user their ruleset was malformed while john was
quietly skipping it. They are now recognised as not applicable, skipped, and
not counted against the file.

**Four lines cannot be read, and that is the correct answer.** They expand to
2,030,625 and 857,375,000 rules. John generates its expansions lazily and its
documentation says it never keeps them all in memory; Hashsmith materialises
them so a program is compiled once and reused, which is the right trade for
every rule anyone writes and the wrong one for these. They are refused with
their ACTUAL size rather than capped silently, so the message says what the
line asks for instead of just that it is too big.

Corpus coverage: **98.4%**. The remaining 1.6% is those four lines.

### ZipCrypto, found by a test that had been failing at 1 in 256

A full-suite run failed on `TestZipCryptoRoundTrip`: a wrong password was
accepted. Twelve reruns passed, which was the answer — ZipCrypto's encryption
header offers ONE check byte, so one wrong password in 256 passes it, and the
test builds a fresh archive each run against a fixed wrong password. It had
been failing roughly one run in 256 the whole time, and the obvious reading of
such a flake is "ignore it".

It was not noise. Every ZipCrypto record Hashsmith produced accepted one wrong
password in 256, so a rockyou-sized run reported thousands of passwords that do
not open the archive, with nothing to distinguish them from the real one.

The entry itself settles it. Its CRC-32 and its payload now go into the record,
and the check byte becomes a cheap gate in front of an exact test: decrypt,
inflate, checksum. The expensive half runs on about one candidate in 256
because the gate rejects the rest, so it costs roughly a 256th of doing it
every time. Measured over 20,000 wrong passwords: **0 accepted**, against the
~78 the byte alone would have let through.

Getting that for the COMMON case needed one more thing. Bit 3 of an entry's
flags means the local header holds zeroes where the CRC and sizes belong, with
the real values in a trailing descriptor that cannot be found without already
knowing the size. Info-ZIP's `zip` — the most common producer of ZipCrypto
archives there is — sets that bit on every entry, so reading only local headers
would have given the exact check to 7-Zip's archives and left `zip`'s on the
weak one. The central directory has what the local header withholds, so it is
read.

The round trip now asserts the record's SHAPE as well as its behaviour, because
a single known password cannot tell the two records apart, and a second test
throws 2,000 wrong passwords at it — where the byte alone would accept about
eight.

### Sweeping every format for the same defect

Two formats had now leaked the same way — a record that kept a short check and
discarded what would have settled it — and neither was visible to a round trip
over one known password, because both cracked the right password perfectly
well. So every format was swept: **353 of them, up to 512 wrong passwords
each. None accepted one.**

A full sweep costs 136 seconds, which is most of a second test suite, so each
format also gets a 100ms slice. That is not a compromise where it matters: the
leaks this looks for live in RECORD parsing, and those verifiers are the cheap
ones that finish all 512 tries well inside the slice. What gets truncated is
the expensive KDFs, where a short check is not a shape the verifier can have
because it compares a full digest. Fifty formats were truncated and the test
NAMES them with their try counts, so a format that quietly stops being swept
shows up in the log instead of passing for coverage. Total cost: 12.5 seconds.

The limits are stated rather than implied. The sweep reliably catches a check
of one or two bytes and cannot catch a four-byte one, so a clean run is the
absence of the cheap mistake and not proof of exactness. And one case it can
never reach is recorded in the test: the short `$zipaes128/192/256$` records
keep WinZip's two-byte verifier and accept one wrong password in 65,536, which
is a property of that record rather than a bug — the `winzip` type reads the
authenticated `$zip2$` form instead, and the extractor emits it whenever the
archive allows.

### Hashcat modes: nine more, and four that were never algorithms

Before implementing anything, every unsupported mode's published record was run
through Hashsmith's own auto-detection. Six cracked already — the format was
there and only the `-m` number was unmapped. Three more were implemented.
Conformance is now **450 of 538 (83.6%)**, up from 441.

Three were the **collider #2** modes. Hashcat splits MS Office 97-2003 and PDF
revision 2 into two stages: `-m 9710`, `-m 9810` and `-m 10410` recover a
five-byte intermediate, and `-m 9720`, `-m 9820` and `-m 10420` take that
answer, appended to the record after a colon, and find the password behind it.
What those five bytes are had to be measured — for MD5 it is
`md5(16×(md5(utf16le(pass))[:5] ‖ salt))[:5]`, the value one step BEFORE the
RC4 key, while for SHA-1 it is the RC4 key itself. Not symmetric, and not
guessable.

Hashsmith needs no two stages: it recovers the password from the bare record in
one pass. So the record those modes produce is accepted, and the appended
answer is used rather than discarded — it settles a candidate after two hashes
instead of three plus an RC4 stream, which is the same shortcut hashcat takes.
A test corrupts the answer and requires the record to stop cracking, because
otherwise the pre-filter could be silently skipped and every test would still
pass.

**The first-stage modes are deliberately left unsupported.** They ask for a key
fragment, not a password — hashcat's own example answer for 9710 is
`$HEX[91b2e062b9]`. Mapping them at a password cracker would report a mode as
supported while never returning what its user wants, and a test now pins that
they stay unmapped.

Four more of the 538 records are not password hashes at all, so the gap was
overstated: `-m 2000` is hashcat's candidate-printing mode, which Hashsmith
spells `--stdout`, and `-m 72000`, `73000` and `74000` hand the hashing to a
Python or Rust program the user supplies at run time. Each now answers with
what it actually is instead of "unsupported hash algorithm". `-m 99999`,
Plaintext, is implemented: the target is the password, which is how you test a
wordlist or a ruleset with the verifier taken out of the way.

**eCryptfs (`-m 12200`) is implemented**, derived from its published vector
rather than from a description. The signature is SHA-512 over the salt and
passphrase, then 65,536 more SHA-512 rounds over the digest — 65,537
invocations, not 65,536, which is exactly the sort of off-by-one a
specification sentence hides and a vector settles in one run.

**WinZip (`-m 13600`) is implemented**, and it is not only a mode number. Its
`$zip2$` record from zip2john names its key size in a field rather than in its
tag, so one type covers AES-128, 192 and 256 where the existing `$zipaes*$`
short form needs three — and the salt length is tied to that field, 8, 12 or 16
bytes, which the published vector settled rather than a reading of the spec.

More to the point, the record carries an **authentication code** the short form
has no room for: ten bytes of HMAC-SHA1 over the encrypted data. The two-byte
verifier alone accepts one wrong password in 65,536 — over a rockyou-sized run,
several thousand "cracked" passwords that do not open the archive. Checking the
authentication code closes that to one in 2^80. A test corrupts only the code,
leaving the verifier intact, because a verifier-only implementation passes
every happy-path test there is.

**`zip2smith` now writes that record too**, which matters more than the mode
number. It had been emitting the short `$zipaes256$` form, keeping the salt and
the verifier and discarding the ciphertext and the authentication code that sit
right behind them in the same entry — so every WinZip record Hashsmith produced
carried a 1-in-65,536 false-accept rate that the archive itself had the data to
eliminate. When the entry's size is known and its ciphertext fits, the record is
now the authenticated one, and `hashcat -m 13600` cracks it: verified against a
real `7z -mem=AES256` archive, and pinned by a test that runs hashcat.

The two fallbacks say why rather than failing: an entry whose local header
declares no size, because bit 3 of its flags puts the sizes in a trailing data
descriptor, and an entry too large to embed. Both still produce a working
record and both now state the false-accept rate in the label, where it used to
go unmentioned.

**WBB4 (`-m 33800`) is implemented**, and it needed a new primitive rather than
a new parser. WoltLab Burning Board 4 stores `bcrypt(bcrypt($pass))` under a
single salt, and what the outer round hashes is the inner round's FULL crypt
string, prefix included. Every bcrypt API in the tree answers "does this
password match?"; this format first needs "what would this password have
produced?", which no compare-only call can give. `bcryptlane` grew a `Digest`
method for it, checked character-for-character against `x/crypto/bcrypt` so a
nested format built on it cannot feed a subtly wrong inner string to the outer
comparison and simply never crack.

Its record is an ordinary bcrypt crypt string and says nothing about being
nested, which is the real difficulty. Auto-detection therefore does NOT offer
it: proposing both readings would double the bcrypt work on every bcrypt
target — the slowest common format there is — to cover one forum product. That
is the same trade already made for `keepass-keyfile`, decided the same way and
recorded in the same place. A test pins that a WBB4 record still detects as
bcrypt and that plain bcrypt does NOT crack it, which is the trap the catalogue
entry warns about.

Adding these turned up a distinction the detectability ratchet did not draw.
That ratchet counts vectors whose own type auto-detection does not offer, and
every one it covered was an ambiguous record that could in principle become
detectable. `plaintext` never can: its record is the password, so any text at
all is a valid one, and a prototype for it would claim every input Hashsmith is
ever given. It is now excluded by name with that reason attached, rather than
the floor being raised by one — raising it would have quietly bought room for a
real detection gap to appear later without failing anything. eCryptfs, whose
`$ecryptfs$` prefix is unambiguous, got the prototype instead.

### A ratchet that a regeneration could quietly unpin

Regenerating the conformance baseline to record those six modes also rewrote
`-m 29441` from CRACKED to TIMEOUT, because the machine was compiling at the
time. A timeout says "too slow to decide", not "this mode broke", which is why
the ratchet ignores it in both directions — but a REGENERATION writes it, and
a mode pinned TIMEOUT is held to nothing. The next real break in it would pass.

One line among hundreds in the diff, and the ratchet would have been a little
weaker with nothing to show for it. A mode already pinned CRACKED now keeps
that pin through a timeout. Nothing else is preserved: a CRACKED that becomes
NOT-FOUND or REJECTED is a real regression and still shows up as one.

### RESOLVED: the MultiBit modes below are implemented, and the missing step was the password

The section that follows is kept because its reasoning was sound and its
conclusion was right at the time — the plausible reading really did fail, and
shipping it would have produced a verifier that rejects every password. What it
could not find was the one step the record does not show, and the step turned
out not to be in the cipher framing at all.

**scrypt never sees the password's bytes.** MultiBit and Bisq are Java programs
and hand scrypt `String.getBytes("UTF-16BE")`, so an ASCII passphrase arrives
with a zero byte before every character. Every combination tried below was
correct about the framing — AES-CBC with the IV in the first sixteen bytes of
the data field, checked against a full block of PKCS#7 padding — and wrong
about the key, for a reason no amount of varying the cipher could reach.

It was found by sweeping four password encodings (raw, UTF-16LE, UTF-16BE,
UTF-16BE with a BOM) rather than more cipher framings. The lesson is narrow and
worth keeping: when a KDF's inputs are salt, parameters and password, and the
first two are right there in the record, the one that is not written down is
the one to vary.

22700, 27700 and 29800 are now all CRACKED against Hashcat's published vectors.

### A mode NOT implemented, and why that is the result

MultiBit HD (`-m 22700`/`27700`) and Bisq (`-m 29800`) looked like the next
cheap wins: their records carry scrypt parameters in plain sight —
`$multibit$3*16384*8*1*<salt>*<data>` — and Hashsmith already has scrypt. They
are not implemented, and the reason is worth keeping.

What was established, against the published vectors: the 32-byte data field is
NOT the scrypt output. Deriving a 32-byte key with the record's own N, r and p
and comparing it directly fails for both. Decrypting the data with that key as
AES — ECB, and CBC under a zero IV and under bitcoinj's constant IV — produces
nothing recognisable under any of the six combinations. So the data is
ciphertext whose key derivation or cipher framing has a step the record does
not show.

The temptation was to implement the most plausible reading and move on. That
produces a verifier that parses every record, rejects every password, and
reports "not found" — the exact failure the 7-Zip refusal existed to prevent,
and one that a self-test vector would have caught only because hashcat
publishes one. Two modes left honestly unsupported are better than two modes
that claim support and waste a user's attack.

What a later attempt should start from: the field layout above is confirmed,
the scrypt parameters are the record's own, and the six cipher framings listed
are ruled out.

### Making the VeraCrypt KDFs cheaper, and a 3x tax found by measuring

The section above concluded that the VeraCrypt timeouts were marginal rather
than inherent. Chasing that turned up three separate costs, and only one of
them was the hash function everybody was looking at.

**crypto/hmac caches a key's inner and outer states — but only for a hash that
can serialise itself.** Otherwise it re-compresses the 64-byte ipad and opad
blocks for every single message, which in PBKDF2 means every single iteration.
None of RIPEMD-160, Whirlpool or Streebog implemented
`encoding.BinaryMarshaler`, so all three were paying it 500,000 or 655,331
times per derived block. Per 20,000 iterations on an M2:

| PRF | before | after | |
|---|---|---|---|
| RIPEMD-160 | 28.27 ms (x/crypto) | 19.83 ms (native) | 1.42x |
| Whirlpool | 107.7 ms | 74.0 ms | 1.46x |
| Streebog-512 | 221.3 ms | 177.2 ms | 1.25x |

RIPEMD-160 came from `golang.org/x/crypto/ripemd160`, which is deprecated and
cannot be given a marshaler. It did not need to: `ripemd.go` already
implemented the family's narrow 5-round path, which IS RIPEMD-160 — only the
constructor was missing. Adding it drops the dependency and takes LUKS and GPG
along for the same gain. The two are pinned against each other at every length
from 0 to 200 bytes, at every split point of a two-part write, through HMAC
with an oversized key, and through PBKDF2 at VeraCrypt's own 192-byte width.

**PBKDF2 output blocks are independent** (RFC 8018 §5.2), so a 192-byte key is
a strict extension of the 64-byte key, not a different derivation. The
auto-detect path derived 64 bytes, tested the common single-cipher case, and
then derived 192 from scratch — repeating every block of the short key on every
candidate that did not match, which when cracking is all of them but one.
`pbkdf2Range` derives a block range, so the short derivation is extended
instead: ten RIPEMD-160 blocks per candidate rather than fourteen, and the
single-cipher hit still stops after four.

**And then the part that was not about cryptography at all.** A single
candidate against `-m 29411` took 7.8 seconds on a machine where one verify of
that record measures 2.57. A stack dump at the verifier answered it: three
calls per run, not one. `doCrack` probes the type and record once up front so a
malformed hash fails loudly instead of silently finding nothing, and
`checkFeasibility` then times its own verify to estimate a rate. Two full
655,331-iteration derivations before the first real candidate. They are the
same measurement, so the probe's duration is now passed to the feasibility
guard, which takes it when it clears the same threshold it would demand of its
own sample. 7.83s to 5.15s on a one-candidate run; the remaining two calls are
the irreducible ones, the probe and the candidate.

Worth noting which of these mattered. The hash work is what the earlier
analysis pointed at, and it was real but bounded — 1.25x to 1.46x. The duplicated
probe was a flat 2.57 seconds nobody had looked for, found only because a
measured time disagreed with a predicted one by 3x and that gap got chased
instead of rounded off.

Conformance: 455 to 458 of 538, with -m 29411, 29431 and 29442 crossing the
20-second per-record timeout. Ten VeraCrypt modes remain over it, and they are
the wide ones — the cascade widths that derive 128 or 192 bytes of key.

### hashcat ships its own algorithm definitions, and they are already installed

Worth knowing before implementing any of the remaining modes: this machine's
hashcat install carries **1,532 OpenCL kernel sources** under
`/opt/homebrew/share/hashcat/OpenCL/`, including `m<mode>-pure.cl` for every
mode still unimplemented here. Those files ARE the algorithm — init, loop and
comp kernels, in readable C. The per-mode record parsers are compiled
(`share/hashcat/modules/module_<mode>.so`), but they disassemble cleanly:
`module_hash_decode` is a few hundred bytes of ARM64 and shows the token
layout, the esalt field offsets and the byte order of every stored buffer.

Three checks that cost little and are worth doing every time:

1. **Confirm hashcat cracks its own example record on this machine first.**
   It does not always: the OpenCL CPU backend fails to build kernels here
   (`shared.cl build failed`), so `-D1` reports "No devices found/left" and the
   default Metal backend must be used instead.
2. **Mutate one record field at a time and see which mutations break the
   crack.** This establishes which fields the algorithm actually reads before
   any code is written.
3. **When generating candidate records to test an assumption, give each one its
   own salt.** hashcat deduplicates by (digest, salt), and several modules set
   the digest from a salt field rather than from the blob — twelve DPAPI
   records sharing an IV collapsed to `1 unique digests, 1 unique salts`, so
   eleven assumptions went untested while appearing to be refuted.

### DPAPI master keys: confirmed groundwork, and an unresolved last step

An implementation of 15300/15310/15900/15910 was written and is NOT committed,
because it does not reproduce hashcat's example vector and a verifier that
silently never cracks is worse than no support — the same failure the hashcat
conformance ratchet exists to catch.

**Confirmed, and worth not re-deriving.** The record is
`$DPAPImk$<version>*<context>*<SID>*<cipher>*<hash>*<rounds>*<iv>*<len>*<blob>`,
where `<len>` counts HEX CHARACTERS, not bytes: 208 for a v1 blob of 104 bytes,
288 for a v2 blob of 144. From `module_hash_decode`: the module requires that
length to be exactly 208 for version 1 and 288 for version 2 and to equal the
blob token's length; it stores `salt_iter = rounds - 1`, so total PBKDF2
iterations are `rounds`; and it sets the digest from the IV, which is why
records differing only in their blob deduplicate.

The decrypted blob is `[0:16]` HMAC salt, `[16:16+macLen]` the stored MAC, and
the last 64 bytes the master key. Hashcat never decrypts the middle — it needs
16 bytes of MAC and the trailing key, so the rest only has to chain. v1 is
3DES-CBC with HMAC-SHA1, v2 is AES-256-CBC with HMAC-SHA512, PBKDF2 output
split key-then-IV (24+8, 32+16). The check is
`HMAC(HMAC(userKey, hmacSalt), masterKey)[:16] == plaintext[16:32]`.

From the kernels: context 1 is `SHA1(UTF16LE(password))`, context 2 the NTLM
hash, context 3 the NTLM hash through PBKDF2-HMAC-SHA256 twice over the SID
(10,000 rounds to 32 bytes, then 1 round to 16), and context 3 alone hashes the
SID with `SID_len + 2` where 1 and 2 use `SID_len`.

**Where it stands.** `module_hash_decode` widens the SID to UTF-16LE one byte
at a time (`strb w11, [x9], #2`), writes `0x80` at offset `2*len+2`, sets
`SID_len = 2*len+2`, and byte-swaps all 32 words of the 128-byte buffer — so
the message SHA1 actually consumes is not simply `UTF16LE(SID)`, and the `0x80`
lands inside it at index 85 rather than past the end. Roughly 250 combinations
of {password hash, SID encoding and marker, IV byte order, iteration offset,
CBC IV source, MAC chain} were tried against the real record and none matched,
so at least one assumption above is still wrong. The DES convention is not it:
`_des_crypt_keysetup` is OpenSSL's, little-endian key words, equivalent to Go's.

A later attempt should start by settling how `sha1_hmac_update_global` consumes
that swapped buffer — ideally by instrumenting hashcat itself rather than by
further inference, since inference has now been exhausted.

### ODF, a fourth attempt and what it narrowed

The earlier verdict on ODF 1.1 and 1.2 (18600, 18400) was reached without the
Hashcat kernel sources. With them, the algorithm is no longer in doubt:

  key    = PBKDF2-HMAC-SHA1(SHA-1(password), salt, iterations, keysize)  [1.1]
           PBKDF2-HMAC-SHA1(SHA-256(password), salt, iterations, keysize) [1.2]
  plain  = Blowfish-CFB(key, iv, data)      [1.1, 64-bit block, Go's CFB fits]
           AES-256-CBC(key, iv, data)       [1.2]
  check  = SHA-1 or SHA-256 of the plaintext against the record's checksum

That was implemented in full and still does not reproduce Hashcat's published
vector: the decryption yields noise, which means the key is wrong before the
cipher is reached. Ruled out by sweep, against the 18600 vector: iteration
counts of 1023/1024/1025, the IV taken from either end of the record's 16-byte
field, PBKDF2 output widths of 16 and 20, and the PBKDF2 password given as the
SHA-1 digest's raw bytes, its lower-case hex, its upper-case hex, and the
password itself. None produced anything but noise.

What is left to check is the record's field mapping. The module's parser reads
thirteen tokens where the record splits into twelve, so one field is being
counted differently from the obvious reading, and the PBKDF2 salt may not be
the field that looks like one. The implementation is not committed, because a
verifier that parses every record and rejects every password is the failure
this project refuses to ship.

### Where every remaining mode stands

Thirty-four modes were unimplemented at the start of this push and twenty-nine
remain. They are not one backlog; they are five, and only one of them is a
matter of getting round to it.

**Deliberately not supported, and already decided (4).** Modes 9710, 9810 and
10410 ask for an intermediate RC4 key rather than a document password —
Hashcat's own answer for 9710 is `$HEX[91b2e062b9]`, not a passphrase — and
Hashsmith recovers the password directly through their "#2" siblings 9720,
9820 and 10420, which ARE supported. That decision is recorded in
hash_extra.go and predates this push. Mode 20510 is the same shape: given the
candidate "t" against its own example record, hashcat answers "hashcat",
because the mode recovers the remaining six bytes itself. A verifier answers
yes or no about the candidate it was handed; none of these four asks that
question.

**Blocked on evidence, not effort (4).** The DPAPI master key modes 15300,
15310, 15900 and 15910. Record layout, blob layout, `salt_iter = rounds - 1`,
the digest's provenance and the per-context derivations are all confirmed and
written down above; roughly 250 combinations of the remaining unknowns were
tried against the real record and none matched. The next step is instrumenting
hashcat, not more inference.

**Blocked on a resource decision (1).** LUKS v2 argon2, mode 34100, whose
example asks for 1 GiB of Argon2 memory at t=4, p=4. That is seconds and a
gigabyte per candidate, and the conformance harness runs modes in parallel, so
landing it without a deliberate decision about memory limits risks the machine
rather than the test.

**Need a primitive Go does not have (7).** Electrum 21700 and 21800 need
secp256k1 point multiplication. MD6 34600 needs MD6. Kremlin 32700 needs
NewDES, including its 256-entry rotor table. BestCrypt 23900 and 24000 need a
bespoke 4 KiB-table KDF and, for v4, Keccak. RACF 8500 and 14200 need the
proprietary RACF DES construction. Each is a self-contained port of a few
hundred lines; none is research.

**Ordinary work, in rough order of cost (13).** 23700 RAR3-p and 25400 PDF
1.4-1.6 both extend machinery already here. 8501 AS/400 shares RACF's kernel.
14500 Linux Kernel Crypto API, 501 Juniper IVE, 31800 1Password 8 (AES-GCM
with the two-secret derivation), 8800 and 12900 Android FDE, 26500 iPhone
passcode, 28100 Windows Hello, 18400 and 18600 ODF. These are the ones where
the only question is time.

### Still open

- 29 unimplemented hashcat modes, categorised in the section above.
  Conformance is 497 of 538 (92.4%) on a quiet machine, with 8 VeraCrypt modes
  still over the per-record timeout.
- John's rule corpus reads at 98.4%. The four lines left expand to millions of
  rules each and are refused by design, so this item is closed.

## Where this actually landed: 527 of 538

The section above is superseded. Every category it listed as blocked or
expensive is now implemented, except two modes and a family that was never in
scope. Conformance is **527 of 538 (97.9%)** with every format verified
against hashcat's own published record, in both directions where the format
permits it.

Closed since that section was written: the thirteen "ordinary work" modes; all
seven that needed a primitive Go lacks (Electrum ×2 via the secp256k1 helpers
already here, MD6, Kremlin/NewDES, BestCrypt v3, RACF and AS/400 via a
transcription of hashcat's libdes tables); LUKS v2, whose resource question is
answered below; both ODF modes; and all four DPAPI modes.

### Three methodological corrections, which mattered more than any single format

**1. Sweeping cannot find a construction outside the space being swept.**

DPAPI was recorded above as "roughly 250 combinations tried, none matched; the
next step is instrumenting hashcat". Both halves were wrong. The failure was
not a parameter, it was the algorithm: DPAPI's key derivation is not PBKDF2.
RFC 2898 hashes the previous block and XORs into an accumulator; DPAPI feeds
the accumulator back into the PRF. In hashcat's loop kernel that is one
identifier — `w0[0] = out[0]` where every other mode writes `dgst[0]`. No
amount of parameter search finds it, because every point in that search space
computes a correct PBKDF2. Reading the kernel that defines the algorithm took
minutes. Four modes fell out at once.

**2. "It decrypts to noise" is not evidence the key is wrong.**

ODF was recorded as four failed attempts, with the note that decryption
"yields noise, so the key is wrong before the cipher". The decryption had been
correct all along. ODF deflate-compresses each part and encrypts the compressed
bytes, so a correct key produces a DEFLATE stream — no readable header, nothing
that looks like a document. Every attempt had decrypted successfully and then
rejected the result by eye. Both modes matched on the first try once the stored
checksum was used as the test instead. When a format ships a checksum, that is
the test; plausibility of the plaintext is not.

**3. hashcat's AES helpers come in two spellings that differ only in swaps.**

`AES128_set_encrypt_key` swaps and then calls `aes128_set_encrypt_key`, which
swaps again, so they cancel; `aes128_encrypt` swaps once. The result is that a
single mode can be genuinely mixed-endian — iPhone passcode (26500) has a
natural-order UID key, group-reversed loop blocks, a group-reversed derived
key, and natural-order class-key blocks. Reading the capitalisation as
decoration rather than as meaning produces a verifier that is wrong in a way no
single test vector explains.

A practical note that unblocked all of the above: **hashcat cannot build any
kernel on this machine through Metal** — Metal compiles from an in-memory
source string and cannot resolve the `#include` of `inc_vendor.h`. Modes that
appear to work are served from a kernel cache built earlier.
`--backend-ignore-metal` forces OpenCL and builds correctly, and is required
for any fresh verification. That is what made "generate a record from my model
and ask hashcat" available as a bisection tool.

### The resource decision, answered

LUKS v2 asks for a gibibyte of Argon2 per candidate at the parameters real
headers use. Workers defaulted to the CPU count, so the default run would have
asked for ten gibibytes at once on this machine and spent its time swapping.
The worker count is now capped by memory as well as by cores, computed from
the cost the record itself declares, with system RAM read per platform and a
conservative fallback. An explicit `-p` always wins. The cap keys on the
RECORD, not the type name, so an operator who does not pass `-t` still gets it.

### What is left, precisely

**Not password verification, and out of scope by design (4).** 9710, 9810 and
10410 are collider modes: they recover an RC4 key, not a password. 20510 is
PKZIP master-key recovery. None is expressible as `verify(target, candidate)`,
which is the contract every type here satisfies.

**BestCrypt v4, mode 24000 (1).** Shares only the `$bcve$` prefix with v3.
Needs scrypt, Keccak, and a choice of Twofish, Serpent or Camellia. x/crypto
has scrypt, sha3 and twofish; Serpent and Camellia would each be a table-heavy
port from scratch. This is the largest single remaining build.

**RACF KDFAES, mode 14200 (1).** Structure fully mapped, so the next attempt
should start here rather than from the kernel:

- Parameters live in field 2's hex, read as 16-bit little-endian values from
  its characters: chars 16-19 give n, and `mem_fac = 2^n / 32` (n=8 → 8);
  chars 20-23 give `rep_fac` (50), and every PBKDF2 stage runs
  `rep_fac * 100` iterations (5000). `salt_iter = mem_fac`,
  `salt_iter2 = rep_fac*100 - 1`.
- Stage 0: the legacy RACF DES hash of the encoded username under the
  EBCDIC-transformed password, via `_des_crypt_encrypt` — STANDARD DES with IP
  and FP, not the `_racf` variant this repo already implements for 8500/8501.
  Eight bytes out, used as an 8-byte PBKDF2 password.
- Stage 1, `mem_fac` times: PBKDF2-SHA256(key, salt, rep_fac*100) → 32 bytes;
  the new salt becomes `U(iteration-1)`'s first 16 bytes followed by those 32,
  48 bytes total; each result is appended to a memory buffer. The first salt is
  the 16-byte record salt followed by `mem_fac` as a big-endian word, 20 bytes.
- Stage 2, `mem_fac` times: `n = key[7] mod mem_fac` selects a 32-byte block
  from the buffer; `key = PBKDF2-SHA256(key, thatBlock, 1)`; the result
  overwrites buffer slot i. Stage 2's starting key is stage 1's last output.
- Stage 3: PBKDF2-SHA256(key, first `(mem_fac-1)*32` bytes of the buffer,
  rep_fac*100) → the 32-byte AES key.
- Check: AES-256-ECB encrypt of the 16-byte encoded username equals the digest.

Two things are still unread and are where the next attempt should look first:
where `salt_buf_pc` — the 16-byte "encoded username" used as both the DES block
and the AES plaintext — is actually populated, since `module_hash_decode` calls
no EBCDIC conversion and no `generic_salt_decode`; and the byte order of the
salt words between `hex_decode`, the esalt, and the non-swapping
`sha256_hmac_update_vector`. Build a forward generator with `mem_fac` and
`rep_fac` at their minimum, emit a record, and let hashcat bisect it — that
technique is what closed DPAPI and it applies directly here.

## Final: 529 of 538, and nothing implementable left

Every hashcat mode that can be expressed as `verify(target, candidate)` is
implemented. RACF KDFAES and BestCrypt v4 closed after the section above was
written, which leaves exactly four modes unimplemented, all for the same
reason: **9710, 9810, 10410 and 20510 are not password verification.** They
recover an RC4 or ZipCrypto key directly from ciphertext structure. There is
no password to check, so there is nothing for this tool's contract to return.
They are out of scope by definition, not by effort.

Four more report REJECTED — 2000 is hashcat's STDOUT pseudo-mode, and 72000,
73000 and 74000 are bridges that run a user-supplied Python or Rust function
as the hash. Neither is a format.

One reports TIMEOUT: 29473, VeraCrypt Streebog-512 + XTS 1536-bit. That is
the conformance harness saying "too slow to decide on this machine", not a
failure — it runs nine records concurrently at two workers each on ten cores.
Run on its own the mode completes in 14.7s inside a 20s budget.

### The last two formats

**RACF KDFAES (14200)** turned out to hinge on two details that give no
signal when wrong. The chained salt takes U(iter-1), the second-to-last
PBKDF2 block — not the output, not the last block. And the AES plaintext is
the userid BUFFER: eight bytes of blank-padded EBCDIC zero-extended to
sixteen, not sixteen bytes of blank padding.

It also settled something about its siblings. hashcat runs RACF and AS/400 on
a DES with IP and FP removed and both permutations moved onto the host — but
the value the record STORES is the composition of all three, which is ordinary
DES. `crypto/des` reproduces the published AS/400 digest directly from the
EBCDIC-mapped password and the EBCDIC userid block. The transcribed libdes
tables are still needed for the kernel-shaped comparison, but the format
itself is simpler than the kernel makes it look.

**BestCrypt v4 (24000)** shares only its prefix with v3: scrypt at N=32768,
r=16, p=1, with a selectable cipher held as an ASCII character in the second
position of the third field. Its salt is stored hex-encoded but is itself
ASCII digits — a second hex decode would halve it and silently derive the
wrong key. AES is verified against the published record; Twofish had no
published vector, so it was verified the other way, by generating a record
and having hashcat crack it. Serpent and Camellia are refused by name rather
than guessed at, because a wrong cipher fails identically to a wrong password
and there would be no signal to develop against.

### Performance, because coverage is not the only axis

Three hash cores were leaving a factor of two on the floor in the same way:
state words held in arrays that the compiler reloaded on every use, and
two-level table indexing on every lookup.

| primitive | before | after | gain |
|---|---|---|---|
| Streebog-512 | 4.52 us | 2.33 us | 1.94x |
| Whirlpool | 1.97 us | 1.05 us | 1.88x |
| RIPEMD-160 | 0.916 us | 0.707 us | 1.29x |

Per 64-byte hash. These are not algorithmic changes — the table-driven
transforms were already the right approach — only changes in how the same
arithmetic reaches the CPU: locals instead of arrays so values stay in
registers, hoisted table rows so each lookup is one index, and unrolling so
rotations and byte offsets become constants. For RIPEMD the win was hoisting
a five-way switch out of a loop that ran it sixteen times per round on a
value that could not change.

Between them these cover twelve VeraCrypt modes. The Streebog VeraCrypt path
went from 13.2s to 7.3s per candidate.

One negative result worth keeping: hoisting RIPEMD's four index tables into
locals, which is what made Streebog and Whirlpool faster, measured as pure
noise. The compiler was already doing it. Not every instance of a pattern is
worth the same.

## The other half: John coverage, which nothing had measured

With every hashcat mode implemented, the remaining question was the one the
hashcat ratchet structurally cannot ask. It always passes `-t`, so it measures
"given the mode number, does this crack the record" and never "is this record
RECOGNISED". For a user moving off John that second question is the whole
experience: John has no mode numbers, so they arrive with nothing but bytes.

So there is now a second ratchet over `john --list=format-tests` — 6353
vectors, 493 formats — driving the real binary with **no -t**. It found real
defects immediately, which is the point.

### What it found

**A core crack-path defect, and a half-finished earlier fix.**
`crackWithDetection` asked "does this decode as an encoding?" before "is this
a hash?", and took the encoding reading whenever one existed.
`normalizeHashInput` knows nothing about hash shapes — it asks only whether a
string decodes to a plausible digest length — and real hashes satisfy that by
accident. A descrypt hash is thirteen crypt-64 characters, which is valid
z-base-32 decoding to eight bytes, exactly a half-MD5. So `crack CCNf8Sbh3HDfQ`
tried mysql323, cisco-pix and half-md5 and never descrypt, while `identify` on
the same input said descrypt correctly.

This was **defect F fixed halfway**: that earlier fix stopped an explicit `-t`
being overruled and left auto-detection, the far more common path, wrong. The
rule is named now (`resolveCrackTarget`) and says what it means.

**sha1crypt agreed with hashcat and disagreed with John**, with the digest
computed correctly for both. The 28-character checksum encodes 21 bytes while
the digest is 20, and the last byte is not agreed: NetBSD, passlib and John
wrap around to `digest[0]`, hashcat pads with zero. Comparing the ENCODED
STRING accepts whichever convention you implement. John accepts both because
it compares the decoded digest; so does this now. **This is the class of
defect a single published vector per format cannot expose — one vector always
agrees with itself.**

**`verifyArgon2` refused `$argon2d$`** citing a Go library that lacks it,
while `internal/argon2d` had been in this repo since KeePass needed it and the
detection table had always claimed `$argon2d$`. identify named a type crack
then rejected.

**A structural predicate outranking a signature.** `isHMailServer` is
70 characters, six non-hex then 64 hex — and `$gost$` is six non-hex
characters, so John's GOST record matched it exactly and, being exclusive,
suppressed the envelope reading entirely. Its own comment already said why
that was wrong: it is TierStructural, "not the TierSignature a record prefix
would earn".

### Dialect, and the discipline of not calling everything dialect

Most of the residue is the same algorithm spelled differently, and that is
worth closing because a John user has John's spelling. Landed: John's format
envelopes (`$md2$`, `$SHA512$`, `$MD4$`, `$gost$`, `$keccak256$`,
`$oracle12c$`, `$django$*1*`, `$LM$`, matched case-insensitively because John
is not consistent); its `<message>#<digest>` HMAC spelling, which is narrow
enough to refuse `$DCC2$10240#user#hash`; either separator in the
`$pbkdf2-hmac-<alg>$` family, which is inconsistent WITHIN each tool rather
than between them; John's RACF KDFAES envelope; and the django-scrypt
package's layout alongside Django core's.

Three things were deliberately NOT called dialect:

- `$pkzip$` is not a renamed `$pkzip2$` — the field layouts differ, so it
  needs a parser, and shipping the rename would have looked like a fix.
- django-scrypt is not a Django core variant; the parameter encoding
  genuinely differs, so it got its own reader.
- Tiger, SunMD5 and xsha have no type here at all. They are missing
  algorithms, and calling them spellings would hide that.

### A measurement that could not see its own subject

The corpus first took one vector per format. Envelope support went in and the
count did not move, because every affected format's first vector is the bare
digest. The corpus is now keyed by format AND record shape — 605 entries over
the same 493 formats — which makes the dialects visible and immediately
surfaced a gap one-vector-per-format had hidden entirely: `gost $gost-cp$`,
the CryptoPro parameter set.

An earlier version of the same problem: 22 formats had been scored on an
EMPTY-password vector, which measures whether empty candidates are tried
rather than whether the format is supported.

### Where it stands

145 -> 210 of 605 records cracked from the record alone, and no entry has ever
reported a wrong password — 605 unfamiliar records and not one verifier
accepted a decoy. hashcat conformance is unchanged at 529 of 538 throughout.

### Continued: 217 of 605, and what the shape-aware corpus found next

Keying the corpus by format AND record shape immediately changed what the
ratchet could say. Instead of "bcrypt: cracked" it now says "bcrypt $2a$:
cracked, bcrypt $2b$: cracked, bcrypt $2x$: not detected" — which is the
difference between a format and a spelling, made visible.

Closed since:

**Kerberos, three separate spelling differences**, each of which made every
record of its kind unreadable. AS-REP etype 23 arrives from John with no
principal at all and '$' where hashcat has ':'; nothing is lost, because for
etype 23 the key is the NTLM hash of the password alone — unlike etypes 17
and 18, which salt with principal and realm — so the principal is decoration
in that record. AS-REP with AES arrives as `<etype>$<salt>$<edata>$<checksum>`:
salt pre-concatenated instead of separate user and realm fields, and the
checksum AFTER the data instead of before. Pre-auth arrives with an extra
empty field. The AES layout was settled by measurement rather than reading —
the record's own fields were fed to the existing key derivation at each usage
number until one matched, which also confirmed usage 3.

**Both AS/400 envelopes.** `$as400des$` keeps hashcat's body; `$as400ssha1$`
also writes the digest BEFORE the profile name.

**PostgreSQL's legacy `$postgre$`**, one character short of the modern
spelling. Invisible until something read the other tool's whole corpus,
because the modern spelling already worked.

### Three things deliberately left alone, and why

- **`$sxc$` is not a renamed `$odf$`.** It carries two extra length fields,
  so it needs a parser. The prefix rewrite would have parsed and then failed.
- **bcrypt `$2x$` parses and fails, correctly.** That variant exists to
  reproduce a sign-extension bug in old crypt_blowfish; Go's bcrypt does not
  implement the bug. Reading it as `$2a$` would report a WRONG answer instead
  of none, which is strictly worse.
- **`$gost-cp$` is the CryptoPro parameter set** — different S-boxes, not a
  different spelling of GOST.

A test-writing note worth keeping. The first AS/400 test asserted that
appending a character to the right password must fail, and it did not. That
is the format, not a weak check: AS/400 DES builds a DES key schedule from
the EBCDIC password and truncates at eight characters, so "AAAAAAAA" and
"AAAAAAAAx" are genuinely the same hash. The wrong password in a negative
test has to differ where the format actually looks.

### The residue

Of 605 records: 217 crack, 344 are not detected, 35 are detected and fail, 9
are refused. The long tail is now per-format parser work — MongoDB, SCRAM,
CHAP, IKE, LastPass, PKCS#12, PKZIP and the NetNTLM/MSCHAPv2 family each
carry a genuinely different field layout rather than a differently spelled
envelope. None of it is cryptography; all of it is reading records.

Still true after every change: no entry has ever reported a WRONG password.

## From 227 to 436: the residue, worked through

That last paragraph called the remaining work "per-format parser work" and
listed the formats. It was right about the character of it and wrong about
the size: the single largest item was not a format at all.

### The lever: John's dynamic engine is one format, not 163

163 of the 335 unrecognised records — nearly half — were `$dynamic_<n>$`.
That looks like 163 formats and is one. John does not write a verifier per
scheme; it writes an evaluator and a table of expressions, and a record names
its expression by number. `$dynamic_9$<digest>$113-` is `md5($s.md5($p))`
over the salt `113-`.

So the work was an evaluator. The table is transcribed from
`john --list=subformats` so it stays checkable against John line by line;
255 of John's 446 expressions are built from hashes this tool has. The
language is small and completely specified by what the table contains:
concatenation, calls whose suffix picks hex or raw bytes or base64, four
variables, literals, and a few reshaping calls (`utf16`, `uc`, `lc`, the
pads).

**Two of John's own printed expressions are wrong**, and both are corrected in
the table with the reason attached. `dynamic_1588` leaves out that ColdFusion
upper-cases its inner digest. `dynamic_1590` describes an AS/400 salt as plain
text when the record stores it already upper-cased, blank-padded and in
UTF-16BE. Both were settled against John's own test vectors — the transcription
is faithful to what John computes, not to what it prints.

Records are read as John writes them: a hex-encoded salt, the `$$U` and `$$2`
markers — looked for **twice**, because a hex-encoded salt encodes the markers
along with it, as PostgreSQL's `dynamic_1015` does — a login before the record,
a digest stored truncated or zero-padded, and LinkedIn's SHA-1 with its first
five hex digits zeroed.

Of the 136 records claimed, every one cracks with the password John ships and
none with any other. The rest are declined at detection rather than claimed and
failed: an expression naming tiger, panama, haval or skein, or a digest not in
the encoding the expression produces (Cisco's PIX and ASA records are
`dynamic_19` and `dynamic_20` but store PIX base64).

The useful half of that work is not the ratchet number. `@dynamic=<expr>@<digest>`
is John's spelling for an expression given on the spot, and it costs a switch
statement once the engine exists — so a scheme this tool has never heard of can
be cracked by writing down what it computes, salt and all, with no code at all.

### Search as a way of reading records

With the engine in place, a mechanical question became worth asking: how many
of the still-unrecognised records are one of those expressions wearing an
envelope? Trying every field of every record as the digest, the salt or the
username against all 255 evaluable expressions takes nine seconds and answers
it without a guess. Fifteen were. Seven got a format of their own — John names
`dynamic_12` "IPB" and `dynamic_4` "OSC" itself — including four
routing-protocol formats whose salt is not a salt but a captured packet.

The same technique settled the keyed-MAC routing formats, where the question
was which MAC rather than which expression: `net-ah` is HMAC-MD5 truncated to
twelve bytes, `rsvp` is the MAC whole, and `ospf` is RFC 5709 — the one part
not visible in the packet being Apad, the 0x878FE1F3 filler written into the
authentication field before the MAC is taken.

**And it recorded two failures, which is the point of using it.** `$hsrp$` and
`$vtp$` went through the same search — every hash of the packet and the key in
either order, the key NUL-padded and repeated to nine lengths, HMAC under each,
the key written over the packet at every two-byte offset — and came out
unexplained. `$sxc$` lines up with `$odf$` field for field and still does not
verify under eighteen variations. A search says nothing about the space outside
the one searched, so all three are left alone with the evidence written where
the reader would have gone. Claiming a record and failing on it is worse than
not claiming it.

### The defect the ratchet was really for

Six records failed for one reason: the password is empty. Chasing that found
two defects, the second worse than the first.

The dictionary reader trimmed every line and skipped the ones that came out
empty. That cost `" secret"` and `"secret "` — a list containing them was being
asked about a word it does not hold, and a recovered password was printed
trimmed, which would send an operator off with the wrong answer. And it cost
the empty password, which is an account with no password at all: the weakest
finding an audit can make and the one it most wants reported.

Removing the trim was not enough. Found-ness was carried by the password being
non-empty — `result.password != ""` — so Hashsmith verified the empty password,
stopped the run on it, and then reported "Not found". The one password it could
never name, however it was reached. `crackedResult` now says whether it found
something, separately from what it found, and the counter follows the same rule
as the reader because the count is what `--skip` and `--limit` slice.

Nothing needs trimming: bufio's line scanner already drops the newline and any
carriage return before it.

### The rest, briefly

**The captured-credential family.** Six formats share one line — user, an empty
field, a domain, three fields carrying the exchange — and two were implemented.
`netlm`, `nethalflm`, `netlmv2` and `mschapv2` are the rest; MS-CHAPv2's
challenge is derived rather than given, after which it is the NTLMv1 computation
exactly. Telling them apart is now done by shape rather than by assumption: a
16-byte response with an 8-byte trailer is LMv2, not v2 with a suspiciously
short blob. Where the shape leaves a real ambiguity both readings are offered in
order. One fix fell out of the same reading — NTLMv2's identity may be stated as
separate user and domain fields or as one `DOMAIN\user`, and only the first was
read.

**Container records, all five of the refused ones.** None needed new
cryptography; each needed its record read as written. `$7z$`'s type field is a
codec discriminator and was being read as a padding length — this tool's own
extractor writes the padding count there, so the misreading held until a record
disagreed. `$luks$` is the partition header verbatim, hex, with every field the
other spellings name at a fixed offset inside it. KeePass writes the size of a
KDB1 header where a cipher id belongs.

**Four formats John reads that this did not**: `azuread` (the password never
reaches PBKDF2 — the NTLM hash does, so anyone holding the on-premises hash can
check a candidate against the cloud record), `known-hosts` (the secret is a
hostname, so cracking one turns an anonymised file back into a list of
machines), `zipmonster`, and John's `dummy`. Plus macOS's two pre-PBKDF2 hashes,
which are offered rather than asserted because their length is the whole
signature and forty-eight hex characters is also a Tiger-192 digest.

### And then the formats themselves

At 436 the not-detected column held no more spellings, so the rest was
implementation. A mechanical check made that precise and is worth keeping: for
every record John ships that Hashsmith did not recognise, try its known
password against every type this tool has. **Nothing cracked.** So there was
no detection gap left anywhere — each remaining entry was a format with
nothing behind it.

What followed was one loop, repeated: read the record, form a hypothesis about
the construction, test it against John's own vector, implement it if it
matched and record the failure if it did not. The password is known for every
vector, which turns "what is this format" from a research question into a
measurement.

It settled, among others: the Kerberos KDC's stored keys (which are the key
rather than a ticket encrypted with it); Java keystores (whose password is
checked by one SHA-1 over the whole store, Sun's "Mighty Aphrodite" constant
included); 1Password's two vault formats; VirtualBox images (where a candidate
costs BOTH iteration counts, because the password protects a key and a second
hash of that key is what the record compares); PuTTY keys (no salt, no
iterations — which is what makes a collected .ppk cheap); Oracle's logon
exchange; Enpass, which is a SQLCipher page MAC and needs nothing decrypted;
HTTP Digest and SASL DIGEST-MD5, which differ in exactly one place; and
LastPass's verifier.

Two of those deserve their own note.

**`openssl enc` is the one place a check had to be strengthened rather than
implemented.** The format has no authentication at all, so the only available
test is that the last CBC block ends in valid PKCS#7 padding — and a wrong key
produces valid-looking padding about once in 256 tries, which over a ten
million candidate run stops on a wrong answer with near certainty. Hashsmith
requires the padding AND that what precedes it is text. A test measures the
difference rather than asserting it: of twenty thousand wrong passwords, 84
produce valid padding and none are accepted. The cost — a file whose first
bytes are binary is not recoverable from a sixteen-byte sample — is the honest
trade.

**And two hashes were worth more than their obscurity.** Skein was already in
the dependency tree; having it made 36 more of John's expressions evaluable.
HAVAL — five output sizes, three work levels, fifteen of John's formats, and
no Go library anywhere — was implemented from the specification and verified
against John's vectors for all fifteen. It made 135 more expressions
evaluable, taking the parseable count from 291 to 426 of 446.

HAVAL's shape is worth stating because two parts of it invite a wrong
"simplification". Its state is eight words whatever the output size, and a
shorter digest is FOLDED out of all eight rather than truncated — so no short
digest is a prefix of a long one, which a test pins. And its padding records
the parameters, so two HAVALs differing only in pass count differ from the
padding onwards. Its constants are the fractional part of pi, computed rather
than copied: the first eight words are a published value (they are Blowfish's
too), which checks the other 128.

### The last stretch, and what a search is for

Past 490 the loop was: sweep, then implement what the sweep explains. Two
sweeps did most of it. One tried iterated digest constructions — five hashes,
five orderings of password and salt, up to eleven hundred rounds — against
every unrecognised record, and returned exactly two hits, both readings rather
than algorithms: FormSpring writes `<digest>$<salt>` where hashcat writes
`<digest>:<salt>`, and dynamic_1013's records carry their inner digest
precomputed in the salt field, so what the record implies is `md5($p.$s)`
rather than the `md5($p.PMD5(username))` John prints. That is the third
printed expression corrected in the table with its reason attached.

Accepting the dollar spelling needed one condition that is easy to miss and
the reason to write a test: **if both halves are hex it is not a salted
digest**, it is two fields of some other format. A first, looser rule proved
that by claiming a Kerberos AS-REP and a routing capture and failing on both.

Formats settled by the same read-hypothesise-test loop: Tezos fundraiser
wallets (whose twist is that the password goes into the SALT, after the
literal "mnemonic" and the email — the plain BIP-39 reading produces a
valid-looking wallet that is not this one), BlackBerry ES10 (a hundred rounds
of SHA-512 in which the salt is touched once and never again), and MDC-2, the
hash you build out of a block cipher when you have no hash, verified against
OpenSSL's published pangram digests.

**And several searches returned nothing, which is the other half of the
method.** `$hsrp$`, `$vtp$`, `$sxc$`, `$lp$`, `$lpcli$`, WoWSRP, GELI,
OpenBSD softraid, STRIP, BKS and Palshop were each put through a bounded space
of the obvious constructions and none reproduced its vector. Every one of
those is recorded where its reader would have gone. A search says nothing
about the space outside the one searched, and claiming a record you cannot
answer for is worse than leaving it alone.

### Where it stands

Of 605 records: **499 crack**, 87 are not detected, 19 are detected and fail,
none are refused. That is up from 217 when the John ratchet was built.

What is left is a long tail of container formats with no implementation — PGP
disk, GELI, OpenBSD softraid, GNOME keyring, KDE wallet, Dashlane, SAP's PSE,
Nokia SL3 — plus two hashes this tool still lacks (tiger and panama, whose
sixteen dynamic expressions each are the last nineteen of John's 446 that do
not parse), and the records deliberately declined with the evidence written
down.

Still true after every change: no entry has ever reported a WRONG password.

## The one place a wrong password could still be reported

That last line was true of the cracking engine and false of the cache in
front of it.

The potfile records `hash<TAB>plaintext` and is keyed by the target string
alone. A 32-character hex digest is a well-formed MD5, a well-formed NTLM, a
well-formed MD4 and a well-formed LM half all at once, so one string can
honestly have four different answers — and the potfile could hold only one of
them. Cracking `8846f7eaee8fb117ad06bdd830b7586c` as NTLM wrote
`password`; asking `--show -t md5` for the same string then answered
`password`, when MD5's preimage for that digest is not known to anybody and
certainly is not that. The salt does the same thing from the other side: one
digest, two `-s` values, two different plaintexts, one cache key.

Neither John nor hashcat has this problem, because both write the format into
the pot line. Copying that would have been the obvious fix and the weaker one:
it repairs nothing already on disk, and a recorded format is only what the
cracking run *believed* at the time.

So every potfile hit is now re-derived before it is reported —
`verifiedPlain` runs the stored plaintext back through `verifyCandidate` for
the type asked for, or for each detected type when none was given. One hash
per hit, which is nothing beside the attack it skips, and it fixes potfiles
that already exist.

The third outcome is the one worth naming. A hit that re-derives is reported;
a hit that verifiably does not is refused with the reason said out loud
rather than silently dropped. But some records cannot be checked from the
plaintext alone, and for those the check returns an error rather than a
verdict. Treating "could not check" as "wrong" would withhold a correct
answer — a wrong report of the other kind — so it is reported as exactly what
it is: an answer nobody here could confirm.

## Nineteen formats that were already implemented, or nearly

The John ratchet's two failure modes say different things. NOT-DETECTED means
there is no reader for the record. NOT-FOUND means the record WAS read, a
type was offered for it, and the password was not found — which for a bare
digest can only mean the right algorithm was never among the candidates.

Nineteen records sat in that second column, and a sweep of every registered
type against each one settled what was actually wrong with them in a single
pass. Seven needed nothing at all: HAVAL-128-4, HAVAL-256-3, RIPEMD-128,
MDC-2, MD5-of-UTF-16LE, Lotus Notes/Domino 5 and Skein-512-256 were all
implemented, correct, and simply not among the types a bare digest of their
width was offered as. Twelve needed a hash this tool did not have.

### Attack order was table order

Fixing the first group meant putting scarce algorithms into the shape table,
and that exposed something worth fixing on its own: detection returned
candidates in the order the prototype table happens to list them, and the
crack loop attacked them in that order. The table is grouped by family for a
reader's benefit, so a 32-character hex string was attacked as MD5, then MD4,
then MD2, then NTLM — with MD2, which no living system emits, tried ahead of
the digest behind every Windows domain.

Candidates are now ordered by the strength of the evidence behind them:
structural readings before shape readings, and within a tier the commonest
algorithm first. That alone makes every ambiguous auto-attack faster, and it
gives the scarce digests somewhere to go — the bottom.

The cost is real and is stated rather than hidden. A 32-character digest now
has twelve candidate types instead of five, so a run that finds nothing takes
longer. The run says so before it starts, names the scarce types it will come
to, and says that `-t` skips them. ZipMonster is the one format deliberately
left out of that list: it is fifty thousand MD5s per password, four orders of
magnitude past everything else of its width, and belongs behind a flag rather
than at the end of every unsuccessful MD5 attack. Its bare spelling is read
now; it is just not guessed.

### Six hashes, and how each was checked

Tiger, HAS-160, Snefru-128, Snefru-256, Whirlpool-0, Whirlpool-T and PANAMA.

**Tiger** needs four tables of 256 64-bit words that the specification does
not print — it prints a program that produces them, seeded on a sentence from
the paper and shuffled by Tiger's own compression function using the table it
is in the middle of rewriting. Running that generator is forty lines;
transcribing four thousand constants is four thousand chances to mistype one.

**HAS-160** is SHA-1 with a different schedule: four groups of twenty steps
over thirty-two words, sixteen of them derived by XOR. The schedule was
transcribed from an eighty-line macro expansion and then checked for the
regularity the specification claims — that the rotation amounts repeat across
all four groups, and that the five registers advance one place per step — so
a mistyped entry would have to survive that as well as the vectors.

**Snefru** is the odd one structurally: no separate compression function, and
the digest width changes the BLOCK size, 48 bytes of message per block at 128
bits and 32 at 256. Its S-boxes came from a table of random numbers rather
than a formula, so there is no generator and all 4,096 constants are carried.

**Whirlpool-0 and Whirlpool-T** are the 2000 and 2001 revisions the ISO
version replaced — one changed the S-box, the next the diffusion matrix, and
nothing else. So they are one round function over different constants, and
what is stored is constants.

**PANAMA** is not a Merkle-Damgård hash at all but the state machine Daemen
later reworked into Keccak's sponge: absorb, then thirty-two blank rounds,
then read eight words out. It carries no message length, because the pull
phase and not the padding is what separates one message from another.

Every one of them was checked twice. Published vectors where they exist, and
then the other direction: Hashsmith computed digests for messages John had
never seen, and John was asked to crack them under the matching format. It
recovered every plaintext. That second check is worth more than a transcribed
constant for exactly the hashes where the constants are generated — three of
my own recollected "published" vectors turned out to be wrong, and the
cross-check is what said so rather than the implementation.

**Post.Office** was settled by search rather than by reading: a bounded sweep
of orderings and single-byte separators against John's vector returned
`md5(salt || 'Y' || password || 0xF7 || salt)` and nothing else.

### Where it stands

Of 605 records: **523 crack**, 81 are not detected, 1 is detected and
deliberately not guessed, none are refused. That is up from 217 when the John
ratchet was built and 499 at the last entry.

445 of John's 446 dynamic expressions now parse. The one that does not is
dynamic_1507, whose `$const` John keeps in its configuration file rather than
in the expression — the expression alone does not determine a digest, and no
amount of hashing will supply it.

Everything left is a container format with no reader: PGP disk, GELI, OpenBSD
softraid, GNOME keyring, KDE wallet, Dashlane, SAP's PSE, Nokia SL3. There is
no remaining record that Hashsmith can read and cannot answer.

## The undetected column, and what reading beats guessing at

With the NOT-FOUND column emptied, everything left was NOT-DETECTED: eighty-one
records with no reader. A sweep of every registered type against every one of
them returned nothing, which settled that none of them was another
already-implemented format in disguise — or so it seemed. Nine of them were
exactly that.

### Records John writes without a marker

John writes several formats bare, in a spelling that carries no prefix at all,
and Hashsmith reads the same formats under a marker. Neither tool is wrong;
the record simply has two spellings and only one was read:

| John writes | Hashsmith read |
|---|---|
| `<packet>$<digest>` | `$netmd5$<packet>$<digest>` |
| `<user>:<digest>` | `$DCC2$10240#<user>#<digest>` |
| `<realm+user>$<key>` | `$krb18$<realm+user>$<key>` |
| `<checksum>$<encrypted>` | `$krb5asrep$23$…` |
| `$dynamic_19$…`, `$dynamic_20$…` | Cisco PIX and ASA |
| `$gost-cp$…` | the CryptoPro parameter set |

The rewrite happens once, in `verifyCandidate`, so the attack loop, the batch
path and the potfile check all see the same record. Each shape is deliberately
narrow: "two fields with a dollar between them" is half the catalogue read
loosely, so the net-md5 reader wants a packet forty hex characters or longer,
the Kerberos one wants a salt that is *not* hex, and the AS-REP one wants an
encrypted part longer than any digest. These are the cases `hash_compat.go`'s
salt rule already declines with "both halves hex means another format's two
fields" — and this is that other format.

The mscash2 spelling leaves the iteration count implicit, so it is read as
Windows' default of 10,240 and the code says so. A domain configured otherwise
needs the spelling that states it, which is a reason to prefer that spelling
and not a reason to refuse this one.

### Ten formats read from their sources

Post.Office was settled by search. The ten after it were not, and one of them
explains why.

An earlier pass put `$palshop$` through a bounded sweep of orderings and
separators and found nothing, and that result is recorded where its reader
would have gone. It was true and it was uninformative, because the
construction is this: MD5 and SHA-1 of the password laid end to end, the hex of
bytes 5 through 30 of that taken *starting from the low nibble of byte 5* so
the string begins mid-byte, the last character overwritten with a nibble from
the front, and the resulting fifty-one characters hashed again. No sweep of
orderings reaches a thing like that. Reading the source does, and it took ten
minutes.

That is the lesson worth keeping from this batch. A search that returns
nothing bounds what was searched and says nothing about the rest — which was
always the claim, and Palshop is what it looks like when the rest is where the
answer was.

The ten: **Outlook .pst**, whose password check is a CRC-32 with neither of
the conventions that make the usual CRC-32, and which is not a password hash
at all — thirty-two bits, unsalted, millions of passwords to a value.
**Microsoft Money**, which upper-cases the password and hashes forty bytes of
buffer rather than the password's own length, so both the case-folding and the
trailing zeros are inside the digest and invisible in the record. **RADIUS**,
where what is recovered is the shared secret between a client and its server —
the user's password is written in the record, because knowing it is what makes
the secret recoverable at all. **EPI**, whose digest contains a NUL because the
C that wrote it measured the key with its terminator. **leet**, which XORs
SHA-512 and Whirlpool over the same two strings in opposite orders. **Nokia
SL3**, whose fifteen-digit unlock code is hashed as the numbers zero to nine
rather than the characters, and whose IMEI is read as hex. **ADX**, a 32-bit
fold printed as eight digits whose own reference vectors include a collision
its author noted as working on a real terminal. **Siemens S7**, an HMAC-SHA1
keyed on SHA-1 of the password, over a challenge anyone on the link to the PLC
can capture. **BitShares**, AES-256-CBC under an unsalted, uniterated SHA-512
— one hash per candidate, on a wallet. And **Palshop**.

BitShares is worth one more line. Its check is the PKCS#7 padding block, and
the block to decrypt is the LAST one with the one before it as the IV — not
the first two, which is what reading the record as "IV then ciphertext"
suggests. Decrypting the first block of the published vector gives
`4c1900745ecfb143…`; the last gives sixteen 0x10 bytes. The padding is at the
end of a message, so the end is where to look.

### DragonFly BSD, and a bug that made two formats out of one

`$3$` and `$4$` are DragonFly's SHA-256 and SHA-512 crypt schemes: the
password, a tag, the salt, hashed once. No iteration count and no stretching —
the shape of sha256crypt with none of its work factor.

Each is two formats because the buffer holding the tag was not the length the
code filling it assumed. On a 32-bit build the bytes after `"$3$\0"` were
nothing; on a 64-bit build they were the next eight bytes of the neighbouring
string — `sha5` for the SHA-256 scheme, `/etc` for the SHA-512 one. Those four
characters are inside the digest, the record cannot say which build wrote it,
so both are offered and either may answer.

The digest encoding carries a second bug of the same family. SHA-512 is 64
bytes and DragonFly's base64 loop emits 62, so two bytes of every `$4$` digest
are simply not in the record. Comparing all 64 fails against every correct
password; comparing the 62 that are there is what the format stores.

One more thing cost twenty minutes and is worth writing down: the file was
first called `crack_dragonfly.go`, and Go reads a trailing `_dragonfly` as a
build constraint for the DragonFly BSD operating system. It dropped the file
from every other build silently, and the failure surfaced as "undefined" at
the call sites, naming functions plainly present in a file plainly in the
package.

### Two checks that are not hashes

Two more formats were read from source in the same pass, and both are worth
naming for what they are rather than for the work of adding them.

**Nuked-Klan** interleaves the forty hex characters of SHA-1(password), one at
a time, with bytes of a twenty-byte site key read cyclically from a stored
offset, and MD5s the eighty bytes that result. The site key is the same for
every account, so it peppers rather than salts — two users with the same
password have the same record — and the offset is one hex digit. What the
elaboration buys over `md5(sha1(password))` is work for the defender.

**Rational ClearQuest** stores a 32-bit sum: table entries indexed by position
plus character, added up over the username and then the password. Nothing
about it is one-way by design — no avalanche, contributions commute, and a
password of the right length can be walked character by character to any
target. Its own reference vectors sit four to a username. A match names an
enormous family of passwords the server would also accept, which for getting
in is sufficient and is precisely why a checksum is not a password.

Outlook's `.pst` belongs in the same paragraph, and so does ADX. Four of the
formats added in this pass are verifiers rather than hashes, and the code says
so at each of them — not as a disclaimer, but because "cracked" means
something different when thirty-two bits are all that stand behind the answer.

### HSRP and VTP: what was outside the space searched

Two records were written down earlier as searched and not found. The note in
`crack_routing_auth.go` said a bounded sweep of every hash of the packet and
the key in either order, the key NUL-padded to nine lengths, HMAC under each
of those keys, and for HSRP the key written over the packet at every two-byte
offset, had reproduced neither vector — and that a search says nothing about
the space outside the one searched.

That was exactly right, and here is what was outside it.

**HSRP** prefixes the packet with the key MD-**padded**: the key, a 0x80,
zeros, and the key's bit length at byte 56 — the precise sixty-four-byte block
MD5 would have produced had the key been the whole message. Then the packet,
then the key again. No sweep of orderings and paddings reaches a construction
with a length field inside it.

**VTP** does not hash the password at all. It repeats it cyclically across
1,563 sixty-four-byte blocks — very nearly a megabyte — and MD5s that down to
a sixteen-byte secret, and it is the secret that brackets the packet. A sweep
over the password was searching the wrong string. VTP also zeroes three fields
of the captured advertisement before signing it: the follower count, the
update timestamp and the checksum, because a switch cannot sign a checksum it
has not written yet.

Both were settled in under an hour by reading John's source, after a search
that had cost considerably more and correctly concluded nothing. The old note
stays where it is, with the answer now attached to it.

### Containers, vaults, and two more the search had missed

Seven more, all read from source.

**GNOME keyring** derives its key by hashing the password and salt once and
then re-hashing the digest alone for the remaining rounds — weaker than PBKDF2
at the same count, and the count is in the record. The plaintext carries its
own MD5 in its first sixteen bytes, so a correct password is a correct
password rather than a collision.

**STRIP** is SQLCipher, and the check is the SQLite header: a correct key
decrypts eight bytes at offset 16 into a page size that is a power of two, a
write-format byte of at most 2, and three bytes SQLite has written as
`40 20 20` since version 3. That is worth about thirty bits — a wrong password
passes about once in a billion, and John checks exactly the same eight bytes.

**LastPass**, in both the browser extension's `$lp$` and the `lpass` command
line tool's `$lpcli$`. Both salt PBKDF2-HMAC-SHA256 with the account's EMAIL
ADDRESS — public, shared across devices, never rotated — and then encrypt a
fixed string. The extension encrypts the literal `lastpass rocks` followed by
two 0x02 bytes, which is PKCS#7 padding written into the constant rather than
computed; the CLI encrypts the first sixteen bytes of "`lpass` was written by
LastPass.\n" in CBC under a stored IV. A third LastPass shape, the sniffed
exchange, was already read. The iteration count in an `$lp$` record dates it:
LastPass's default went 500, then 5,000, then 100,100.

**World of Warcraft's SRP-6 verifier** and **Eggdrop's bot password** were both
on the earlier searched-and-not-found list, and neither is a hash of the
password in any arrangement. WoW stores g^x mod N with
x = SHA-1(salt ‖ SHA-1(USER:PASS)) — modular exponentiation, not a digest, and
the account name is part of x, which is why the record carries it. Eggdrop
runs Blowfish keyed on the password and encrypts a fixed 64-bit block: the
password is the KEY and the record is a ciphertext.

Eggdrop cost an hour longer than it should have, and the reason is worth
writing down. The cipher is ordinary Blowfish; what is not ordinary is the
encoding. Eggdrop's base64 alphabet is crypt(3)'s sixty-four characters in a
different order — lower case before upper, where crypt puts upper first — and
decoding with crypt's ordering yields plausible bytes that never match. Two
wrong theories about the cipher were chased and discarded before the alphabet
was checked.

**OpenBSD softraid** came last in this batch and is the clearest example of a
design choice showing through the record. The disk's real keys — thirty-two
AES-XTS-256 keys, two kilobytes of them — are not derived from the passphrase
at all; they sit on disk encrypted under a key that is, in ECB with no
chaining. Changing the passphrase re-masks those two kilobytes rather than
re-encrypting the volume, which is why it takes no time. The check is an
HMAC-SHA1 over the unmasked keys keyed on the SHA-1 of the masking key, so
twenty bytes agree or nothing does.

Two vaults finished the batch, at opposite ends of the care taken.
**andOTP** encrypts its backup — every TOTP secret its owner has — under one
unsalted, uniterated SHA-256 of the password, so a candidate costs one hash
and one GCM tag check. **Clipperz** goes four SHA-256s deep with the account
name and salt both folded in, and then exponentiates, but its modulus is 256
bits. Neither extreme changes the answer much: the tag and the verifier both
say yes or no exactly, and the work factor is the only thing between them.

### Where it stands

Of 605 records: **571 crack**, 33 are not detected, 1 is detected and
deliberately not guessed. That is up from 523 two entries ago and 217 when the
ratchet was built.

## Six more, and a bug kept on purpose

**Dashlane** is PBKDF2-HMAC-SHA1 at 10,204 iterations — not 10,000, not
10,240; a number with no round shape to it, which is what a typed constant
looks like. What identifies a correct password is that the plaintext inflates:
the vault is DEFLATE-compressed XML, and arbitrary bytes essentially never
form a valid DEFLATE stream, let alone one spelling an XML declaration. Two
details of the container are not deducible from the record — the IV comes out
of OpenSSL's `EVP_BytesToKey` over the PBKDF2 output (whose key half is then
discarded, because the AES key is the PBKDF2 output itself), and the
compressed stream starts six bytes into the plaintext.

**Padlock** is PBKDF2-HMAC-SHA256 inside AES-CCM, and its tag cannot be
checked at all: Padlock hands its additional authenticated data to SJCL still
base64-encoded, so the tag is computed over the wrong bytes and no independent
implementation reproduces it. John says so in its own source and checks the
plaintext instead. That leaves CCM's confidentiality half, which is plain
counter mode — no CBC-MAC needed to read the plaintext out.

### `$2x$`: the variant that exists to reproduce a bug

In 2011 a sign-extension mistake was found in crypt_blowfish. Packing the
password's bytes into 32-bit words, it read each byte as a SIGNED char: a byte
below 0x80 is unaffected, one at or above it arrives negative, and OR-ing that
into the accumulator sets every bit above the byte too. ASCII passwords hash
identically either way — which is why the bug survived fourteen years — and
anything with a byte above the ASCII range hashes to something much weaker.
The fix introduced `$2y$` for the corrected schedule and `$2x$` for the old
one, so existing records could be marked rather than silently reinterpreted.

A `$2x$` record therefore does not mean "an old hash". It means "a hash
deliberately kept buggy", and the password behind one is by construction
likelier than average to be non-ASCII — which is the only reason the
distinction was worth keeping at all.

It needed no second bcrypt. The bug is in how bytes become words and nothing
else, and the schedule reads eighteen words of four bytes with the key cycled:
seventy-two byte positions. Work out what the buggy reader would have produced
at those seventy-two positions, write it down as a seventy-two-byte key, and
an **ordinary** bcrypt over that key produces the `$2x$` digest exactly. Per
group, a byte at or above 0x80 fills every EARLIER byte of its own four with
0xFF and touches nothing after it — a rule the tests pin directly, alongside
the property that an ASCII password produces no filled byte at all.

### The three PGP formats

`$pgpsda$`, `$pgpdisk$` and `$pgpwde$` share a designer and not much else.

The SDA and Disk derivations are OpenPGP's iterated-and-salted S2K written the
wrong way round: instead of hashing a stream of salt-then-password to a byte
count, they hash the salt once and then the password followed by a counter
byte, once per iteration — and the counter is eight bits, so it wraps every
256 rounds and contributes nothing after the first pass. Both verify by having
the derived key encrypt its own first block: CAST5 for the SDA, and for Disk
whichever cipher the algorithm number names — 3 is CAST5, 4 Twofish, 5 through
7 AES-256. A volume reporting 3 was made by a PGP old enough that the disk it
protects is probably older still.

WDE stores no verifier at all. It stores the encrypted session key, and a
password is right when what comes out is correctly OAEP-padded — a stronger
check than any verifier, since the padding carries a twenty-byte hash of the
empty label that a wrong password would have to reproduce by accident. Its
S2K is the properly-written one, and its IV is not stored either: sixteen zero
bytes with the first set to 8, a constant PGP's own source calls
`kPGPdiskUserWithSymType`.

### Two where the verifier is not a hash of anything

**SAP's PSE** stores the PIN protecting an SAP system's private keys
**encrypted under a key derived from that same PIN**. So a candidate is checked
by deriving the key, encrypting the candidate with it, and asking whether that
is what the file holds — which makes the verifier exactly as long as the
password, and means an eight-character password and a nine-character one
cannot collide because the stored lengths differ.

**S/Key** stores the last one-time password the server accepted. The scheme
walks a hash chain backwards: the client hands over the value one step before
the stored one and the server hashes it once. Cracking it means walking the
chain forwards from a candidate passphrase, sequence-number times — so a LOW
sequence number is cheaper to attack than a high one, and the more an account
has been used, the faster its passphrase falls. That inverts the usual
relationship between a record's age and its cost.

S/Key's four hashes all fold their digest to sixty-four bits, and SHA-1's fold
is specified in words rather than bytes. The two surviving words are written
big-endian — the digest's own order — and a little-endian reading of the same
words produces a plausible-looking answer that never matches. The other three
vectors passed while that one did not, which is exactly the shape of a
byte-order mistake and is why it was worth having four.

### Two keystores, and a fold with nothing in it

**Bouncy Castle's keystore** has a flaw worth stating because it changes what
a hit means. The MAC key's length is in the record, and Bouncy Castle wrote it
in BITS — so a keystore saying 20 has a TWO-BYTE MAC key. Sixteen bits of key
over a twenty-byte HMAC means many passwords produce the right MAC, and John
marks such a record inexact for exactly that reason. A match on a BKS store
with a short MAC key says the candidate is one of a large family the keystore
would accept; a match on the UBER variant, where the check is a full SHA-1 of
the decrypted store, says it is the password.

**GELI** does not encrypt the disk under the passphrase. It encrypts a master
key, and stores up to two independently wrapped copies so a volume can have
two passphrases — so a hit says which slot it opened as well as that it opened
one. Between the PBKDF2 and the key there are two steps, each of which turns a
correct password into what looks exactly like a wrong one. The PBKDF2 output
is folded through HMAC-SHA512 **under an empty key**, because a passphrase and
a key file are combined by HMAC in the general case and a volume with no key
file still goes through the fold with nothing in it. Only then do the
encryption and authentication keys come out, by HMAC of a single byte — 0x01
and 0x00 — under the folded result. Skipping the empty fold cost an hour and
produced digests that were wrong in the way a wrong password is wrong.

### AFS, and a seam between two implementations

AFS's string-to-key is two functions with a length test between them, and the
test is on the PASSWORD: eight characters or fewer take one path, nine or more
the other. That is not a tuning choice. It is the seam between CMU's original,
which ran the password through crypt(3) and therefore could never use more
than eight characters of it, and Transarc's replacement, which fixed that by
hashing the whole thing with DES in CBC. Both are still live, because a cell
full of short passwords is still using the first.

The CMU path repays a second look. It XORs the password with the cell name,
replaces any resulting NUL with 'X', hands eight bytes to crypt(3) under the
fixed salt "p1", takes eight characters out and shifts each left one bit to
make room for DES's parity. A password longer than eight characters loses
everything past the eighth; a cell name longer than the password contributes
its own bytes to the key.

Kerberos 4's record has no digest in it at all. It is a captured ticket, and a
password is right when the decrypted ticket spells "krbtgt" where the ticket
format says it should — decrypted in propagating CBC, where each block's
feedback is the XOR of the plaintext and ciphertext before it rather than the
ciphertext alone. One corrupted block ruins everything after it, which is the
property Kerberos wanted and the reason that trailing word is worth checking.

### SunMD5, and a hash whose cost depends on the password

SunMD5 is MD5 iterated at least 4,096 times, and what is interesting is not
the count but what gets hashed. On each round a coin is flipped from the bits
of the current digest, and when it comes up heads the round hashes a kilobyte
and a half of Hamlet as well. Half the rounds are cheap and half are
expensive, and WHICH is decided by the digest — so the cost of checking a
password depends on the password and cannot be scheduled in advance.

That was deliberate. A fast MD5 gets its speed from fixed buffer sizes and
unrolled loops, and a hash whose block count depends on data it has not
computed yet defeats both. Twenty years on it is also why SunMD5 resists SIMD
batching: the lanes fall out of step on the first coin flip.

The constant phrase is 1,517 bytes and the text is 1,516. The implementation
hashes the C string constant's trailing NUL along with the words, and leaving
it out produces a digest that is wrong in exactly the way a wrong password is
wrong — three vectors failing identically, with nothing to say which of a
dozen details was at fault. It was the last byte.

### What a 56-bit key looks like from the inside

Kerberos 5's DES database keys (etypes 2 and 3) use the string-to-key it
inherited from Kerberos 4, and it is the clearest illustration here of what
"56-bit key" means in practice. Password and salt are folded to fifty-six bits
by XOR-ing eight-byte blocks together, with every other block reversed — bit
by bit as well as byte by byte, so the fold does not simply cancel repeated
input — and the result is used as a DES key to CBC-MAC that same input. The
MAC is the key.

Everything after the fold is defence against DES's own quirks. Parity bits are
inserted, carrying no information because DES ignores them. And if the result
lands on one of the sixteen weak or semi-weak keys — the ones whose encryption
is its own inverse, or nearly — the last byte is flipped. Hitting one by
accident is about a one in 2^52 event; the check exists because "about never"
is not "never".

### OpenVMS, KWallet, and OpenOffice's broken SHA-1

**OpenVMS** is the oldest password function here that is still a password
function rather than a checksum, and it is built out of number theory: the
password and username fold into one 64-bit value and that value goes through
a polynomial evaluated modulo 2^64 − 59, the largest prime that fits in a
quadword. Purdy proposed it in 1974 — inverting means extracting roots modulo
a prime, evaluating is a handful of multiplications. Two things have aged
badly and both are in the record: the output is sixty-four bits, and unless
the account carries the PWDMIX flag the password is upper-cased first, which
is why VMS passwords are case-insensitive and the keyspace is smaller than it
looks. The record also carries the username, packed three characters to a
sixteen-bit word, because the username is part of the hash.

**KWallet** hashed the password in SIXTEEN-BYTE BLOCKS, each SHA-1'd and then
re-hashed two thousand times on its own, with the results concatenated. A long
password is therefore not stronger in the way it looks: its blocks are
stretched independently, so the work is the same per block rather than per
password, and a fifty-six-byte key made of four fourteen-byte slices is four
independent chains rather than one. KDE 4.13 replaced it with PBKDF2-SHA512.
Its check is that the decrypted header holds at least twelve NULs in
fifty-two bytes — the entries are length-prefixed UTF-16, so half of every
ASCII character is a zero byte, and garbage from a wrong key has about two.

**OpenOffice's SHA-1 is wrong.** Its padding unconditionally fills to sixty
bytes into the block and, when the message ends 52 to 55 bytes into one, adds
a whole extra block of zeros before the length — where the specification would
have fitted the padding into the space already there. For every other length
the two agree exactly, which is why the bug went unnoticed: it shows on one
message length in sixteen. Files written by affected versions carry the buggy
digest, so both are computed and either may answer. That required writing out
SHA-1's compression function, because the difference happens after the last
point a `hash.Hash` lets anything in.

One mistake in this batch is worth recording. ODF was already implemented, for
hashcat's spelling, and writing the new file with `cat >` destroyed it. The
build caught it immediately — a duplicate `case "odf"` — and git had the
original, so nothing was lost but time. The fix was to extend the existing
reader with John's `$sxc$` spelling and the buggy digest rather than replace
it, which is what should have happened in the first place.

### Where it stands

PKZIP got the same treatment as ODF: John writes `$pkzip$` where hashcat
writes `$pkzip2$`, and the only difference is that an entry in the older
spelling carries one two-byte check value where the newer carries two. The
pair exists because different zip tools wrote different things into the last
bytes of the encryption header — some the top of the CRC-32, some the top of
the DOS timestamp — and the newer record names both so a reader need not
guess.

### n-fold, and what a key derivation looked like before hashes were assumed

A Kerberos 5 TGT under a 3DES key carries no digest at all: a password is
right when the decrypted ticket contains the word "krbtgt", which it does
because a ticket names the service it is for.

The derivation is the one place in Kerberos where the design shows its age.
Password, realm and username are concatenated and **n-folded** — rotated right
thirteen bits at a time, with the rotations added together using end-around
carry — which mixes a short string into a fixed width without using a hash
function, because in 1993 a hash function was not something a protocol assumed
it had. The folded bits become a 3DES key by inserting a parity bit after
every seventh, and that key is then run through the DK function twice: once
with the literal string "kerberos", once with the constant `00 00 00 03 AA`,
which is what distinguishes a key derived for encryption from one derived for
signing.

### Oracle, where the thing recovered is the password itself

The two logon exchanges before `$o5logon$` share a property with SAP's PSE:
Oracle encrypts the password under a key derived from the password, so a
candidate is checked by decrypting and asking whether what came out is the
candidate. There is no digest anywhere in the record.

The key derivation predates everything else here. Username and password are
concatenated as upper-cased UTF-16BE and DES-CBC-encrypted twice — once under
the fixed key `0123456789ABCDEF`, then again under the last ciphertext block
of that first pass, with the second pass's last block becoming the key. Oracle
has been doing this since version 6 and the fixed key has never changed, so it
is a constant in every client and server in the world.

What the generations differ in is what that key unlocks. 9i wraps a 3DES
session key and then the password under it, with two fixed entropy strings
folded into a SHA-1 along the way — one of which is seeded with NINETEEN bytes
of a previous digest, its last nineteen rather than its first, which is the
sort of detail only a reference implementation records. 10g wraps an AES
session key at each end, XORs the two halves and MD5s them into the key the
password is under, so both the server's and the client's contributions are in
the record and either alone is useless. In 10g the eight bytes of the fold
become a 128-bit AES key by zero padding, so half that key is known to
everyone.

### FEAL-8, and a salt that is not one

Sybase's PROP hash — Replication Server's, not ASE's — is built out of FEAL-8
and a linear congruential generator, and neither is doing what it looks like.

FEAL was proposed in 1987 as a faster DES and is the cipher that taught
cryptography how to do differential and linear cryptanalysis: FEAL-4 fell to a
handful of chosen plaintexts, FEAL-8 to a few thousand, and by 1994 the family
was finished. Its round function is arithmetic rather than table-driven — two
bytes added and the sum rotated left two places, which is the entire
nonlinearity, and which is both why it was fast and why it broke.

The generator is Microsoft's `rand()`, seeded from the record's own first byte
and used to produce SALT bytes, one per block. Sixteen bits of state and a
published recurrence means the whole "salt" sequence follows from a value
stored in the clear beside the hash. And the way a salt byte is mixed in means
only the first two bytes of a block take it directly, with the rest chaining
off the second — so a change in byte three or later of the password cannot
affect byte zero of the key.

What gets encrypted is a fixed sentence. Literally a joke, about a fly, and it
is the plaintext behind every Sybase PROP hash in the world.

### The last two

**Lotus Notes 8.5** is the user.id file rather than the directory entry, and it
is the other half of a format already half-implemented: Domino 5, 6 and 8 are
what the SERVER stores, and this is what the CLIENT carries. It reuses IBM's
substitution table — already in the tree for Domino 5 — in a different
arrangement, then encrypts a blob with RC2, which Go ships nowhere, so RC2 had
to be written out.

RC2 is worth the detour. Rivest designed it in 1987, kept it a trade secret,
watched it get reverse-engineered onto sci.crypt in 1996, and published it as
RFC 2268 in 1998. The design carries its era in a way no modern cipher does: it
separates the KEY LENGTH from the EFFECTIVE key length, and the key schedule
deliberately destroys entropy to hit the effective number — one byte is masked
down and the whole schedule re-derived backwards from it. That existed so a
product could ship a long key and export a short one. Lotus asks for 64
effective bits from an eight-byte key, so nothing is discarded, and the real
strength is the password's.

Three things in the derivation look like mistakes. One is: the code computes
SHA-1 of a fixed string plus the password, stores it, and then reads only the
sixteen bytes BEFORE it, so the SHA-1 never reaches the key. One is not: a
`memset` with its value and length arguments transposed writes the right byte
anyway, because both are 16. And the last is the format's real problem — there
is no iteration count anywhere. A candidate costs one proprietary hash and one
RC2 decryption of under a hundred bytes.

**BestCrypt** — the container, not the volume; `$bcve$3$` was already read and
is a different product — derives its key with PKCS#12's function from RFC 7292,
the one designed for .pfx files in 1996 and still alive because certificate
tooling never replaced it. Jetico did not take it unmodified, and both changes
are invisible from the interface:

The block width v is 64 for every hash, including SHA-512, whose block is
actually 128. A conforming PKCS#12 implementation and BestCrypt therefore
disagree on SHA-512 containers, and neither can read the other's files.

Because v is 64 and the password buffer is filled to v rather than to a whole
number of the password's own lengths, a password longer than 31 characters is
TRUNCATED under SHA-512 and Whirlpool: the buffer holds 64 bytes of UTF-16,
which is 32 characters. The SHA-256 path does grow its buffer. So the same
passphrase is stronger in a SHA-256 container than in a Whirlpool one, and
nothing tells the user which they chose.

The IV is eight bytes where AES wants sixteen, and the two modes disagree about
the other eight: CBC repeats them, XTS zero-fills them. John's source says
"isn't BestCrypt great?" at that line, which is as close to a specification as
this part of the format gets.

### Phase 5, started for real

Format parity closed the question the roadmap opened with, and it moved the
bottleneck. John ships 118 converters; this shipped 48. A format nobody can
convert into a record is a format nobody cracks, so the long tail here was
reachable only by someone who already held a record — which is the opposite of
how an engagement goes.

Seven landed first, chosen because each had a working verifier and no way to
reach a real file: Java KeyStore, Bouncy Castle BKS and UBER, GNOME Keyring,
KDE KWallet, OpenSSH known_hosts, Apache htdigest, PuTTY .ppk.

The two Java-shaped stores are the same problem twice. The password is checked
over EVERY byte of the store body and nothing in the header says where that
body ends, so finding the offset means walking each entry to its end —
certificates, chains, timestamps — and throwing all of it away. The walk IS the
extractor. Two details in that walk would pass a casual read: a version 1
keystore does not name each certificate's type where version 2 does, so reading
the name anyway eats the first two bytes of the certificate; and BKS states its
MAC key size in BYTES at version 1 and in BITS at version 2, for the same
twenty-byte SHA-1 key.

A salted KWallet keeps its salt in a separate file beside it. An extractor
reading only the wallet cannot produce a usable record, so the sibling is
looked for and named when missing.

known_hosts is the one where the thing being cracked is a HOSTNAME, not a
password, and where unhashed entries must be skipped rather than emitted: they
are already the answer.

PuTTY version 3 is refused rather than misread. It replaced the unsalted pair
of SHA-1s with Argon2, so a version 2 record built from a version 3 file would
be answered WRONGLY, not merely fail. That is the worse outcome and the sniffer
reports the version digit to prevent it.

The test method matters as much as the extractors. Five of the seven are tested
by REBUILDING the container from the record John's own format test carries, and
asserting the extractor reproduces that record byte for byte and that it still
cracks with the password the original file used. A hand-written fixture only
proves the parser agrees with its author.

Extractors: 48 → 55. Container sniffers: 18 → 23. Sixty-three of John's
converters still have no counterpart.

---

Of 605 records: **603 crack**. One is detected and deliberately not guessed
(ZipMonster, whose 50,000 MD5s per candidate are four orders of magnitude past
everything of its width). One cannot be answered from the record at all:
`dynamic_1507` names a constant that lives in John's configuration file, so the
expression alone does not determine a digest. Every other format John reads,
Hashsmith reads.
