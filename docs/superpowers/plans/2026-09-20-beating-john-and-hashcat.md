# Beating John and Hashcat: Measured Gap Analysis and Roadmap

**Date:** 2026-09-20
**Status:** Phases 0, 1 and 3 complete. Phase 2 complete except for the 83
unimplemented modes. Phase 4 substantially done. Phase 6 resolved. Phase 7
started. Phase 5 not started.
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

### Phase 5 — Extractors `[L]`

The 62 in §2.6, ordered by how often an engagement produces that file:
Kerberos (`krb`/`kirbi`/`ccache`) → `pcap`/`wpapcap` → `putty`/`openssl`/`pem` →
Java `keystore`/`bks` → `DPAPImk` → wallets and password managers.

- [ ] Before adding any, add the round-trip test that is missing: generate a real
      container, extract, crack with the known password. The zip/7z/pdf leads in
      §4 exist because no such test runs.

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

- [x] A round-trip property test over every codec, to the standard hashes are
      held to. Fuzz targets still outstanding
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
