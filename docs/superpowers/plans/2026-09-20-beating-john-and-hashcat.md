# Beating John and Hashcat: Measured Gap Analysis and Roadmap

**Date:** 2026-09-20
**Status:** Analysis complete, roadmap proposed, not yet approved
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
| **CRACKED** — correct password recovered | **324** | **60.2%** |
| **REJECTED** — mode resolves, canonical record refused by the parser | 124 | 23.0% |
| **NO-SUCH-MODE** — `unsupported hash algorithm: <n>` | 83 | 15.4% |
| **NOT-FOUND** — record parses, KDF runs, correct password reported missing | 7 | 1.3% |

Reproduce: `/private/tmp/.../scratchpad/xtest3.py`.

**Read this against the README.** The README's comparison table claims 457
universal formats and 503 numeric Hashcat aliases against Hashcat's "450+".
That framing counts registry entries. Measured against the only test Hashcat
itself supplies, Hashsmith handles 60.2% of Hashcat's modes. The 457 number is
not false, but it is not the number a user experiences.

### 1.1 The 124 rejections are concentrated, not scattered

| Parser | Modes refused |
|---|---|
| TrueCrypt / VeraCrypt header | **36** |
| LUKS | 12 |
| SNMPv3 | 7 |
| GPG secret-key, Kerberos AES | 4 each |
| sshng (record + ciphertext) | 5 |
| IKE-PSK, PDF R*, KeePass, MongoDB, PEM, VirtualBox, Episerver, Werkzeug | 2 each |
| descrypt, Juniper, Oracle, PeopleSoft, PostgreSQL | 1 each |

One parser — TrueCrypt/VeraCrypt — accounts for 29% of the rejected set. A
handful of parser fixes recovers most of this column. This is the cheapest
coverage in the entire document.

A small number of these are legitimate record-shape differences rather than
defects (Hashcat's `-m 12` PostgreSQL example carries the username differently
than Hashsmith expects). Most are not.

### 1.2 The 7 silent failures are the most serious class

These parse, run the KDF, and report "Not found" for the password Hashcat says
is correct. A user cannot distinguish this from an uncrackable password.

```
-m 23     Skype
-m 131    MSSQL (2000)
-m 9500   MS Office 2010
-m 12800  MS-AzureSync PBKDF2-HMAC-SHA256
-m 28503  Bitcoin WIF private key (P2WPKH, Bech32), compressed
-m 30903  Bitcoin raw private key (P2WPKH, Bech32), compressed
-m 30904  Bitcoin raw private key (P2WPKH, Bech32), uncompressed
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

### Phase 0 — Stop corrupting the user's input `[S]`

Everything in §2.1. This is a few days of work that fixes defects in five
commands at once, and it is a prerequisite for trusting any later measurement.

- [ ] Route all input through one explicit layer with a documented contract: no
      comma splitting unless the user opts in, no whitespace trimming, `--` to end
      flag parsing, `-` means stdin everywhere
- [ ] Stop the normalizer rewriting the target when `-t` is explicit
- [ ] Fix the two-byte loss on non-seekable wordlists
- [ ] Send `crack` results to stdout; keep progress on stderr
- [ ] Add `--version`, and per-command `--help`

**Acceptance:** all six defects in §2.1 have a regression test; the argv and file
paths of the §1 harness produce byte-identical results; `crack ... | head` works.

### Phase 1 — Make the self-test measure the right boundary `[M]`

- [ ] Add a CLI-level conformance harness that drives `hashcat --example-hashes`
      end-to-end through the real binary and records CRACKED / REJECTED /
      NO-SUCH-MODE / NOT-FOUND per mode
- [ ] Commit the current 324/538 as the baseline and fail CI on regression
- [ ] Add the equivalent for `john --list=formats`

**Acceptance:** `make conformance` prints the §1 table; CI fails if CRACKED drops.

### Phase 2 — Burn down the Hashcat record gap `[L]`

With Phase 1 as the scoreboard, in strict value order:

- [ ] The 7 silent NOT-FOUNDs (§1.2) — wrong answers are worse than missing ones
- [ ] TrueCrypt/VeraCrypt header parser — **36 modes**, the single biggest win
- [ ] LUKS (12), SNMPv3 (7), sshng (5), GPG (4), Kerberos AES (4)
- [ ] The remaining long-tail rejections
- [ ] The 83 unimplemented modes, prioritised by engagement frequency

**Acceptance:** CRACKED ≥ 480/538 (89%). State the residue and why.

### Phase 3 — Ship something a stranger can install `[M]`

Nothing above reaches a user while every install path is broken or stale.

- [ ] Fix `setup.cfg` `package_data` and `MANIFEST.in`
- [ ] Release workflow producing static binaries for linux/darwin × amd64/arm64
      and windows/amd64, plus GPU-enabled macOS builds
- [ ] npm and Homebrew consume the release binaries instead of building from source
- [ ] Dockerfile, shell completions, `--version` wired to the tag

**Acceptance:** on a clean machine with no Go toolchain, all three install paths
yield a binary whose `--version` matches the current tag.

### Phase 4 — Candidate quality `[M]`

- [ ] Replace `common.txt` with a real password list, or fetch one on first run
- [ ] Ship rule files, and `--rules` names resolve without a path
- [ ] Implement John's rule dialect: reject flags, `*`/`@` references, character classes
- [ ] Auto-discovery finds wordlists where john and hashcat install them

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

### Phase 6 — The GPU decision `[XL, or drop]`

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

### Phase 7 — Win where neither competitor is trying `[M-L]`

This is where "best encoding/decoding toolkit" is actually earned. Phase 0 fixes
six of this area's blockers for free; the rest is additive.

- [ ] Known-answer vectors and fuzz targets for every codec, to the standard hashes
      are already held to
- [ ] Recursive magic decode — peel layers until the output stops looking encoded
- [ ] Chained pipeline syntax so a recipe is one invocation
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
