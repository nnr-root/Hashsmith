# Hashsmith

Hashsmith is a terminal-first toolkit for encoding, decoding, hashing, cracking, and identification.

The project is now Go-first:
- Core CLI is implemented in Go.
- Python package is a thin launcher kept for PyPI distribution compatibility.
- npm package builds and runs the Go binary.

## Installation

### Homebrew
```bash
brew tap s4l1hs/hashsmith
brew install hashsmith
```

### PyPI
```bash
pip install hashsmith-cli
```

Notes for PyPI:
- Python 3.9+ is required for the launcher.
- Go 1.21+ is required at runtime on first execution (the launcher builds the local binary).

### npm
```bash
npm install -g hashsmith-cli
```

Notes for npm:
- Go 1.21+ is required at install time (`postinstall` builds the binary).

### Direct Go Build
```bash
cd hashsmith/go_hashsmith
go build -o ../../hashsmith ./cmd/hashsmith
cd ../..
./hashsmith --help
```

## Quick Start

Input is always **positional** — inline text, a quoted comma-list, or a file (one input per line):
```bash
hashsmith encode -t base64 "hello"
hashsmith decode -t base64 "aGVsbG8="
hashsmith hash -t sha256 "secret"
hashsmith hash -t keccak256 -e base64url "secret"
hashsmith encodings                                  # list every codec/transform
hashsmith hash -t md5 "password, admin, letmein"    # comma-list → one hash per input
hashsmith hash -t md5 words.txt                      # file → one hash per line
hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99          # built-in common.txt wordlist
hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99 -w custom.txt   # or -w / --wordlist
hashsmith identify "5f4dcc3b5aa765d61d8327deb882cf99, 8846f7ea…"  # identify several at once
```

Auto-detect & crack — no need to name the hash type:
```bash
hashsmith 5f4dcc3b5aa765d61d8327deb882cf99   # detects the type, then cracks it
hashsmith hashes.txt                          # cracks every hash in a file (one per line)
hashsmith crack 5f4dcc3b5aa765d61d8327deb882cf99   # same auto-detection via the crack command
```
When the type is ambiguous (e.g. a 32-char hex could be MD5/MD4/NTLM) every candidate is tried in turn.

`crack` sets a script-friendly **exit code**: `0` when every target was cracked,
`1` when at least one was not, `2` on a usage or format error.
Specifying `-t <type>` skips detection and is faster.

Identify shortcut — `-i` takes an inline value (in `'…'` or `"…"`), a comma-list, or a file path:
```bash
hashsmith -i "aGVsbG8="
hashsmith -i hash.txt
```

> Multi-input is comma-separated, so a single input that itself contains a comma should be given via a file (one line).

### Encoding and decoding types

Run `hashsmith encodings` (or `hashsmith codecs`) for the complete catalogue.
Alongside Hex, Base32/58/62/64/85, URL, Morse, and the classical transforms,
Hashsmith supports Base32hex, Crockford Base32 and z-base-32, Base36, RFC 9285
Base45, Bitcoin/Flickr/Ripple Base58, Base58Check, Bech32/Bech32m, Z85, basE91,
Bubble Babble, MIME/raw/padded Base64
variants, PEM, gzip/zlib with Base64 transport, C-style hex escapes, Adobe
ASCII85, JSON/form escaping, A1Z26, ROT5/13/18/47, and UTF-16/UTF-32 in both
byte orders. Decoders accept
practical variants such as unpadded Base32/Base64, embedded ASCII whitespace,
and separated hexadecimal:

```bash
hashsmith encode -t base45 "Hello!!"             # %69 VD92EX0
hashsmith decode -t z85 "HelloWorld"
hashsmith encode -t base58check "payload"
hashsmith encode -t base58ripple "XRP alphabet"
hashsmith encode -t bubblebabble "pronounceable bytes"
hashsmith encode -t bech32 -k hs "checksummed payload"
hashsmith encode -t gzip "compress me"            # Base64-transported gzip
hashsmith encode -t utf16le "Hashsmith"           # hexadecimal UTF-16LE bytes
hashsmith decode -t hex "0x68:61:73:68-73 6d 69 74 68"
```

### Hash types

Hashsmith supports **457 universal formats**, and every one is validated against
a known-answer vector before shipping — no unimplemented stubs, no unvalidated
crypto. Most hashes are auto-detected, so naming a type is optional. When you want
to pin one, pass `-t <name>`; run `hashsmith types` for the full registry. Beyond
the raw digests, Hashsmith covers salted placements, nested digests, and HMAC
natively:

```bash
hashsmith crack -t md5 <hash> -s 12345678 -S suffix   # md5($pass . $salt)
hashsmith crack -t md5 <hash> -s 12345678 -S prefix   # md5($salt . $pass)
hashsmith crack -t md5-md5 <hash>                     # md5(hex(md5($pass)))
hashsmith crack -t hmac-sha256 <hash>:<salt>          # HMAC-SHA256, key = password
hashsmith crack -t hmac-sha256-saltkey <hash>:<salt>  # HMAC-SHA256, key = salt
hashsmith hash -t sha512_256 -e base64url "secret"    # encode raw digest bytes
hashsmith types                                       # list every supported -t type
```

Hashsmith also accepts familiar Hashcat mode numbers and John format labels for
formats with the same candidate semantics. These are aliases attached to the
same universal format records, not separately counted hash implementations. The
namespaced spelling is clearest in scripts; bare Hashcat mode numbers work too:

```bash
hashsmith crack -t hashcat:0 5f4dcc3b5aa765d61d8327deb882cf99
hashsmith crack -t 1410 '<sha256>:<salt>'             # sha256($pass.$salt)
hashsmith crack -t john:raw-sha256 <hash>
hashsmith crack -t john:dynamic_2 <hash>              # md5(hex(md5($pass)))
hashsmith crack -t 15100 '$sha1$20000$salt$checksum'  # NetBSD/Juniper sha1crypt
hashsmith crack -t 8900 'SCRYPT:N:r:p:b64salt:b64dk'
hashsmith crack -t 10900 'sha256:rounds:b64salt:b64dk'
hashsmith crack -t 32900 'PBKDF1:sha1:rounds:b64salt:b64digest'
hashsmith crack -t 25700 '<murmur-hash>:<32-bit-seed>'
hashsmith crack -t 34810 '$BLAKE2$<blake2b-256>:<salt>'
hashsmith crack -t 35100 '$sm3$<salt>$<checksum>'       # SM3 crypt
hashsmith crack -t 16400 '{CRAM-MD5}<opad-state><ipad-state>' # Dovecot state record
hashsmith crack -t 15400 '$chacha20$*<counter>*<offset>*<iv>*<plain>*<cipher>'
hashsmith crack -t 18800 '<base64-record>'             # Blockchain second password
hashsmith crack -t 31500 '<dcc-hash>:<username>'       # NT hash candidates
hashsmith crack -t 33500 '$rc4$40$<drop>$<cipher>$<offset>$<plain>'
hashsmith crack -t 35300 '$krb5tgs$23$…'               # NT hash candidates
hashsmith crack -t 16800 '<pmkid>:<ap>:<sta>:<essid-hex>'
hashsmith crack -t 22400 '$aescrypt$1*<salt>*<iv>*<key>*<hmac>'
hashsmith crack -t 9700 '$oldoffice$0*<salt>*<verifier>*<hash>'
hashsmith crack -t john:oldoffice '$oldoffice$3*<salt>*<verifier>*<hash>'
```

The compatibility aliases cover the common raw digests, UTF-16LE digests,
HMAC, Unix crypt, Windows credentials, generic `hash:salt` hashes, seeded
checksums, PBKDF1/PBKDF2, and nested digest modes. Run `hashsmith types` for the
canonical names. Digest-wrapped bcrypt, Apache Shiro 1 SHA-512, AIX, GRUB2,
macOS, Django, Passlib, NetIQ/Adobe SSPR, AS/400, Samsung Android, AuthMe, PHPS,
and CubeCart records also accept their corresponding mode numbers.

Covered today: the full **raw / salted / iterated / HMAC** digest family
(MD2/MD4/MD5/SHA-0/SHA1/SHA2/SHA3/SHAKE/SM3/Keccak/RIPEMD-160/BLAKE2b/BLAKE2s,
salted with `-s`/`-S`, expanded `digest-digest` nested forms, and HMAC-MD5,
SHA1/SHA2/SHA3/RIPEMD-160 in both key-modes), the Unix crypt(3)
family (`descrypt`/`md5crypt`/`sha256crypt`/`sha512crypt`/`bcrypt`), MySQL, MSSQL,
PostgreSQL, LM/NTLM/NetNTLM, Kerberos, Argon2/scrypt, generic PBKDF2 with
MD5/SHA1/SHA224/SHA256/SHA384/SHA512, PBKDF1-SHA1, GRUB2 PBKDF2-SHA512, and every
encrypted-container format handled by the `*2smith` extractors.

Raw additions include MD2, SHA-0, SM3, SHA-512/224, SHA-512/256, legacy
Keccak-224/256/384/512, SHAKE128-256, SHAKE256-512, BLAKE2b-256/384, and legacy Windows
LM. Explicit checksum modes cover CRC-32, CRC-32C, CRC-64/ECMA, Adler-32,
FNV-1a 32/64, xxHash32/64, MurmurHash3-32, seeded CRC32, original MurmurHash,
MurmurHash64A, seeded MurmurHash3/CRC32C, CRC-64/Jones, Skip32 known-plaintext,
and raw DES/3DES/AES-128/192/256-ECB, ChaCha20, and RC4 DropN known-plaintext records;
because short checksums are highly ambiguous, specify those with `-t`.

Application, device & framework hashes: **Django** (PBKDF2, scrypt, Argon2,
bcrypt-SHA256, and legacy salted hashes), **phpass** (WordPress/phpBB3),
**Drupal 7**, **MediaWiki**, **vBulletin**, **Redmine**, **LDAP** (`{SHA*}`/`{SSHA*}`/`{CRYPT}`),
**Cisco-IOS 4/8/9**, **Cisco-PIX/ASA**, **Citrix NetScaler**, **Juniper NetScreen**,
**macOS 10.8+** (`$ml$`), **Atlassian** (`{PKCS5S2}`), **JWT** (HMAC), **SIP digest**,
**Python Passlib PBKDF2**, **Werkzeug PBKDF2/scrypt**, **ASP.NET Identity v2/v3**,
**SolarWinds Orion legacy/v2**, **ArubaOS**, `sha1(CX)`, **SM3 crypt**,
**Mojolicious signed cookies**, **Japanese tripcodes**, **Blockchain second
passwords and legacy AES-OFB wallets**, **phpass-over-MD5**, **Symfony legacy
passwords**, and **Bitwarden** — all vector-tested.

Canonical application records also cover **Veeam VBK**, **Microsoft Online
Account**, **SecureCRT MasterPassphrase v2**, **KNX IP Secure**, **TeamSpeak 3**,
Hashcat's NT-hash-input **NetNTLMv1/NetNTLMv2** modes, **Dahua/Besder authentication**,
**Simpla CMS**, **RSA NetWitness**, and **Radmin3**.

Database, auth & directory hashes: **MySQL** (3.23, 4.1+, and MySQL 8 `$A$`
`caching_sha2_password`), **MSSQL**, **PostgreSQL** (incl. **SCRAM-SHA-256**),
**MongoDB SCRAM-SHA-1/SHA-256** stored and server keys, Red Hat **389-DS
`{PBKDF2_SHA256}`**, **Sybase ASE**, **SAP CODVN B & F/G** including the
RFC_READ_TABLE representations from Hashcat 7701/7801,
**NTLM/NetNTLM**, **Kerberos** including AES AS-REP and NT-hash-input modes,
Active Directory **DCC/DCC2** (mscash/mscash2),
**CRAM-MD5**, **Dovecot CRAM-MD5 states**, **DCC/DCC2 plaintext and NT-hash-input modes**,
**IPMI2 RAKP HMAC-SHA1/HMAC-MD5**, **DNSSEC NSEC3**, legacy
**Oracle H**, and **iSCSI CHAP** — all vector-tested.

### Wireless, wallets & disk encryption

Every entry is validated against a known-answer vector before shipping (802.11i /
RFC 4493 for WPA, go-ethereum's keystore test data for Ethereum, the reference
wallet examples for Bitcoin/Electrum, real VeraCrypt/BitLocker/LUKS volumes):

| `-t` type | Format | Covers |
|---|---|---|
| `wpa` | `WPA*01*…` / `WPA*02*…` / `pmkid*ap*sta*essid` | WPA/WPA2 PMKID and EAPOL 4-way handshake (HMAC-MD5/SHA1, AES-CMAC) |
| `wpa-pmkid` / `wpa-pmk` | `pmkid:ap:sta[:essid]` or `WPA*01/02*…` | Hashcat 16800 passphrase and 16801/22001 raw-PMK records |
| `wpa-hccapx` / `wpa-hccapx-pmk` | 393-byte hccapx as hex | Legacy Hashcat 2500 passphrase and 2501 raw-PMK EAPOL records |
| `ethereum` | `$ethereum$p*…` / `$ethereum$s*…` | Web3/Geth keystore v3 (PBKDF2 and scrypt) |
| `ethereum-presale` | `$ethereum$w*…` | Ethereum pre-sale PBKDF2/AES wallet |
| `bitcoin` | `$bitcoin$…` | Bitcoin/Litecoin wallet.dat (iterated SHA-512 + AES-256-CBC) |
| `electrum` | `$electrum$1*…` | Electrum wallet salt-type 1-3 (double SHA-256 + AES-CBC) |
| `aescrypt` / `multibit-key` / `terra-wallet` | Native Hashcat records | AES Crypt, MultiBit Classic/bitcoinj, and Terra Station wallets |
| Bitcoin WIF/raw key address modes | Mainnet P2PKH, P2WPKH, or P2SH(P2WPKH) address | Hashcat 28501-28506 and 30901-30906, compressed and uncompressed public keys |
| `metamask` / `metamask-short` / `exodus` | Native Hashcat records | MetaMask AES-GCM and Exodus scrypt/AES-GCM wallets (26600/26610/28200) |
| `pkcs8-pem-*` / `jks-private-key` | Native `$PEM$` / `$jksprivk$` records | PKCS#8 PBKDF2-SHA1/SHA256 and Java KeyStore private keys (24410/24420/15500) |
| `vmware-vmx` / `virtualbox-aes*` | Native `$vmx$` / `$vbox$` records | VMware VMX and VirtualBox AES-XTS records (27400/27500/27600) |
| `office-old*` | `$oldoffice$0/1/3/4*…` | Office 97-2003 MD5/SHA-1 + RC4, Hashcat 9700/9800 and John `oldoffice` |
| `veracrypt` / `truecrypt` | `veracrypt:<header-hex>` or `$veracrypt$<salt>$<data>` | AES/Serpent/Twofish-XTS single ciphers and two-/three-cipher cascades; RIPEMD-160, SHA-256, SHA-512, Whirlpool, and Streebog-512 standard/boot schedules; legacy Hashcat 6211-6243 and 13711-13783 families plus current 29311-29343 and 29411-29483 families |
| `bitlocker` | `$bitlocker$…` | BitLocker (1M-round SHA-256 + AES-CTR VMK check) |
| `luks` | `$luks$…` (via `luks2smith`) | LUKS v1 — AES/Twofish/Serpent × XTS/CBC-ESSIV/CBC × SHA-1/256/512/RIPEMD-160/Whirlpool |
| `luks-{sha1,sha256,sha512,ripemd160}-{aes,serpent,twofish}` | `$luks$…` (via `luks2smith`) | Strict KDF/cipher selections corresponding to Hashcat 29511-29543 |
| `phpass` / `drupal7` | `$P$…` / `$H$…` / `$S$…` | WordPress, phpBB3, Drupal 7 |

```bash
hashsmith 'WPA*01*<pmkid>*<ap>*<sta>*<essid_hex>' -w wordlist.txt   # auto-detected
hashsmith '$ethereum$s*262144*1*8*<salt>*<ct>*<mac>' -w wordlist.txt
hashsmith '$bitcoin$96*…' -w wordlist.txt
hashsmith crack -t veracrypt 'veracrypt:<header-hex>' -w wordlist.txt
hashsmith luks2smith -f volume.luks -o luks.hash && hashsmith luks.hash -w wordlist.txt
hashsmith crack -t 29522 luks.hash -w wordlist.txt  # require SHA-256 + Serpent
```

The 29511-29543 mode numbers select the same KDF/cipher matrix as Hashcat, but
they consume Hashsmith's compact `luks2smith` record. Hashcat's native split
records include a large encrypted payload and use an entropy check, so the two
record strings are deliberately not presented as interchangeable.

Serpent, Whirlpool, and Streebog are implemented from spec and validated against
their published test vectors (Serpent also against the real LUKS Serpent volumes),
so the single-cipher VeraCrypt/LUKS configurations are all covered. `whirlpool`,
`streebog256`, and `streebog512` are also available as standalone `-t` hash types.

> Still out of scope: VeraCrypt/LUKS **cipher cascades** (e.g. AES-Twofish-Serpent)
> and the GOST "Magma"/Kuznyechik block ciphers — single-cipher volumes only.

Flexible arguments — flag order doesn't matter and every flag form is accepted:
```bash
hashsmith -w=rockyou.txt hash.txt        # flags first
hashsmith hash.txt -w rockyou.txt        # target first
hashsmith hash.txt --wordlist=rockyou.txt
hashsmith hash.txt --wordlist rockyou.txt
```
`-w x`, `-w=x`, `--wordlist x`, and `--wordlist=x` are all equivalent, and the
hash/file target may appear anywhere among the flags.

## Attack modes

Choose the attack with `-M`:

```bash
# Dictionary (default) — try each word in a wordlist, optionally with mangling rules
hashsmith crack -t md5 <hash> -w rockyou.txt
hashsmith crack -t md5 <hash> -w rockyou.txt -r              # built-in mangling rules
hashsmith crack -t md5 <hash> -w rockyou.txt --rules my.rule # a custom rule file

# Brute-force — every combination over a charset, lengths -n..-x
hashsmith crack -t md5 <hash> -M brute -C abcdefghijklmnopqrstuvwxyz -n 1 -x 6

# Mask — a targeted brute-force where each position has its own charset
hashsmith crack -t ntlm <hash> -M mask --mask '?u?l?l?l?l?d?d'

# Hybrid — a wordlist with a mask appended (or prepended) to every word
hashsmith crack -t md5 <hash> -M hybrid -w words.txt --mask '?d?d?d?d'              # password2024
hashsmith crack -t md5 <hash> -M hybrid -w words.txt --mask '?d?d?d' --mask-first   # 123password

# Markov — brute-force ordered by likelihood (likely characters first)
hashsmith crack -t md5 <hash> -M markov -C ?l -n 1 -x 8 -w rockyou.txt              # trained on a wordlist
```

**Markov** ordering trains a first-order statistical model from a wordlist —
which characters commonly start a word, and which commonly follow which — then
enumerates the same brute-force keyspace with likely characters tried *first*. It
covers exactly the same candidates as `-M brute`, just in a far smarter order, so
realistic passwords surface early. Trained on the built-in list by default; pass
`-w` to train on your own. (Example: `test` was found in 17k tries vs brute-force's
335k.)

**Hybrid** = dictionary + mask. Each word is extended by every expansion of the
mask, so `summer` + `?d?d?d?d` tries `summer0000 … summer9999`. It captures the
single most common password shape — a base word plus a trailing year, digits, or
symbol — far more cheaply than brute-forcing the whole length. `--mask-first`
puts the mask in front of the word instead.

```bash
# Combinator — join every word of one list with every word of another
hashsmith crack -t md5 <hash> -M combinator -w left.txt --wordlist2 right.txt
```

**Combinator** = wordlist × wordlist. Every left word is concatenated with every
right word (`super` + `man` → `superman`), for passphrase-style passwords built
from two real words that neither a plain wordlist nor a mask would reach.
`--w2` is a short alias for `--wordlist2`.

**Mask placeholders:** `?l` a-z · `?u` A-Z · `?d` 0-9 · `?s` symbols · `?a` all
printable · `?h`/`?H` lower/upper hex · `?b` any byte. Define up to four custom
sets with `-1`…`-4` (referenced as `?1`…`?4`), escape a literal `?` as `\?`, and
any other character is a literal. `--increment` tries shorter lengths first.

```bash
hashsmith crack -t md5 <hash> -M mask --mask '?1?1?1?1' -1 '?l?d'   # 4 chars, each a-z or 0-9
hashsmith crack -t md5 <hash> -M mask --mask '?a?a?a?a' --increment # lengths 1..4
```

## Candidate generation (`--stdout`)

Any attack mode can emit its candidate stream to stdout instead of cracking —
useful for previewing a mask or ruleset, estimating a keyspace, or piping into
another tool. No hash is required.

```bash
hashsmith crack --stdout -M mask --mask '?u?l?l?d?d'        # print every masked candidate
hashsmith crack --stdout -M hybrid -w words.txt --mask '?d?d?d?d'
hashsmith crack --stdout -w words.txt --rules best64.rule   # words transformed by the ruleset
hashsmith crack --stdout -M mask --mask 'ab?d' | wc -l      # count a keyspace
```

Output is single-threaded and ordered — the exact sequence the attack would try.

## Mangling rules

Dictionary mode can transform each word with **mangling rules**. Use the curated
built-in set with `-r`, or supply your own rule file with `--rules <file>` — the
standard `.rule` syntax is supported, so existing rulesets work unchanged. Each
line is one rule: a sequence of single-character commands applied to every word.

```bash
hashsmith crack -t md5 <hash> -w words.txt -r                 # built-in rules
hashsmith crack -t md5 <hash> -w words.txt --rules best64.rule
hashsmith rules best64.rule Password                          # preview/validate a rule file
```

Common commands (positions/counts are base-36 digits: 0-9 then A-Z for 10-35):

| Cmd | Effect | `Pass` → |
|-----|--------|----------|
| `l` `u` `c` `C` | lower / upper / capitalise / invert-capitalise | `pass` `PASS` `Pass` `pASS` |
| `t` `TN` | toggle all / toggle char at N | `pASS` |
| `r` `d` `f` `q` | reverse / duplicate / reflect / dup each char | `ssaP` `PassPass` `PassssaP` `PPaassss` |
| `{` `}` `[` `]` | rotate L / rotate R / del first / del last | `assP` `sPas` `ass` `Pas` |
| `$X` `^X` | append / prepend char X | `Pass1` (`$1`) · `1Pass` (`^1`) |
| `sXY` `@X` | replace all X→Y / purge all X | `sso`→`Paoo` · `@s`→`Pa` |
| `oNX` `iNX` `DN` `xNM` | overwrite / insert / delete / extract | — |
| `<N` `>N` `_N` `!X` `/X` | reject unless len&lt;N / &gt;N / ==N / lacks X / contains X | — |

```
# example.rule — one rule per line, '#' starts a comment
c $1                 # Capitalize + append 1  → Password1
c $2 $0 $2 $4        # Capitalize + '2024'    → Password2024
so0 sa@ c            # leet o→0, a→@, cap      → P@ssw0rd
```

## Performance

Hashsmith runs on the CPU across all cores. For the salt-independent raw digests
that dominate cracking (MD5, SHA-1/224/256/384/512, NTLM, MD4, RIPEMD-160,
BLAKE2), the hot loop hashes each candidate straight into a stack buffer and
compares raw bytes — no hex encoding, no per-candidate heap allocation — and
worker attempt-counters are batched to avoid cache-line contention. Combined,
these lift single-target MD5 brute-force from ~1.8 MH/s to ~20 MH/s on an 8-core
laptop. Multi-hash mode (below) multiplies that further when cracking a dump.

Measure throughput on your own machine with the `benchmark` command:

```bash
hashsmith benchmark                 # a common set of hash types
hashsmith benchmark -t sha256       # a single type
```
```
md5            20.42 MH/s
sha256         14.05 MH/s
ntlm            6.28 MH/s
bcrypt         76.54 H/s
```

For a reproducible end-to-end comparison against John and Hashcat, use the
same deterministic dictionary and synthetic target for all three tools:

```bash
hashsmith benchmark --compare
hashsmith benchmark --compare --gpu -t md5
hashsmith benchmark --compare -t sha256 --candidates 1000000 --repeat 5 --json comparison.json
hashsmith benchmark --compare --hashsmith ./hashsmith --john ./run/john --hashcat ./hashcat
```

The target password is deliberately the final dictionary entry. Reported time
is the median wall-clock recovery time and includes process startup, input
parsing, kernel initialization and result reporting; this measures the actual
one-command workflow rather than mixing each project's incompatible internal
benchmark mode. Missing executables are marked `skipped`, never assigned an
invented score. JSON reports include the platform, logical CPU count, Go
version, candidate count, every individual run, and SHA-256 fingerprints for
the wordlist and available binaries. A Metal/OpenCL build can add `--gpu` to
exercise Hashsmith's GPU dictionary path; formats without a dictionary kernel
fall back to Hashsmith's optimized CPU verifier and say so explicitly.

## GPU acceleration (experimental, opt-in)

Hashsmith ships as a **pure-Go, statically-linked, cross-platform binary** with no
GPU dependency — that is the default and what every install gets. GPU support is
**opt-in** behind a build tag, so it never compromises the default build:

```bash
go build                 # default: pure Go, no cgo, no GPU
go build -tags opencl    # cross-vendor GPU backend — NVIDIA / AMD / Intel / Apple, any OS
go build -tags gpu       # Apple Metal backend (macOS only)
```

The **OpenCL backend** (`-tags opencl`) is the portable one: the same kernels run
on every GPU vendor via OpenCL — the same approach that lets hashcat span all
cards. On a discrete NVIDIA/AMD GPU these kernels run at GH/s; the integrated
Apple M2 used for development reaches ~150 MH/s. All five hash kernels were
verified bit-identical to the CPU on the M2's OpenCL.

Check status (and run a correctness self-test + throughput probe):

```bash
hashsmith gpu
# GPU acceleration: available — OpenCL (Apple M2)   # or Metal, per build
#   self-test: MD5, MD4, NTLM, SHA-1 and SHA-256 mask kernels match CPU ✓
#   throughput: 42.91 MH/s (MD5, 1048576/dispatch)
```

The Metal MD5 kernel is compiled at runtime (no offline shader toolchain needed)
and is **verified bit-identical to the CPU** on every run before use — GPU crypto
is only trusted once proven against the reference. On the integrated Apple M2 GPU,
`hashsmith gpu` reports both paths:

```
throughput: 47.45 MH/s (MD5, transfer-bound)          # CPU-generated candidates
in-kernel brute: cracked "zzzzz" — 140.89 MH/s        # candidates generated on the GPU
```

Generating candidates **in-kernel** (decoding each brute-force keyspace index on
the GPU, so nothing is transferred and only a match flag returns) reaches
~141 MH/s — **~7× the CPU fast path**, even on the small integrated M2 GPU — and
it is verified by cracking the worst-case final index of the keyspace.

`crack` uses it via `--gpu` (**MD5 dictionaries and rules; MD5, MD4, NTLM,
SHA-256, and SHA-1 brute/mask/multi-target**, `-tags gpu` build):

```bash
hashsmith crack -t md5 <hash> -M dict -w candidates.txt --gpu
hashsmith crack -t md5 <hash> -M brute -C ?l -n 1 -x 6 --gpu
hashsmith crack -t md5 <hash> -M mask --mask '?u?l?l?l?d?d' --gpu
```

GPU dictionaries use million-candidate streaming batches to amortize buffer and
command-submission overhead, and CPU-generated rule candidates join those same
batches. On the development M2, a 10M-candidate end-to-end MD5 comparison
measured Hashsmith at 8.95 MH/s, John at 6.78 MH/s, and Hashcat at 4.88 MH/s;
results include startup and therefore should not be treated as universal kernel
speed rankings. Hashsmith's optimized CPU dictionary path can still win on
short or I/O-bound jobs, so GPU remains an explicit choice.

On a full a–z⁶ keyspace (309M candidates) the GPU finishes in **~3.9 s vs ~24 s on
the CPU — ~6×**, for both brute and mask.

`--gpu` also cracks a **whole dump of MD5 hashes at once** (multi-target on the
GPU): every generated candidate is checked against all targets via an on-device
binary search, at almost no extra cost. Cracking 100 hashes over an a–z⁵ sweep
ran at **~130 MH/s vs ~12 MH/s on the CPU — ~10×**:

```bash
hashsmith crack -t md5  dump.txt -M mask --mask '?l?l?l?l?l' --gpu
hashsmith crack -t ntlm dump.txt -M mask --mask '?l?l?l?l?l' --gpu   # NTLM too
```

NTLM (MD4/UTF-16LE) has no CPU hardware acceleration, so its GPU gain is largest:
a 50-hash NTLM dump ran at **~165 MH/s vs ~6 MH/s on the CPU — ~27×**. SHA-256 —
even though the CPU has hardware SHA — still runs **~10× faster** on the GPU (~142
vs ~14 MH/s). The gain grows with keyspace size; for tiny keyspaces the CPU
wins (GPU dispatch has per-batch latency), so `--gpu` is for big brute-force runs.
Without a GPU-enabled build, or for an unsupported type, `--gpu` prints a notice and
falls back to the CPU automatically.

**Status & roadmap.** Verified today: the backend seam (kernels plug in without
touching the CPU engine), a Metal MD5 kernel checked bit-identical to the CPU,
in-kernel brute-force and mask generation, multi-target on-device matching (crack
a whole dump on the GPU), for **MD5, MD4, NTLM, SHA-256, and SHA-1**, all wired into
`crack --gpu`, capability detection, and graceful CPU fallback. Multi-target
sweeps keep several command buffers in flight (pipelined dispatch) and use large
in-kernel batches. On the integrated Apple M2 these two together are throughput-
neutral versus a single large batch — the GPU is compute-bound, already saturated
by one dispatch — but they keep it continuously fed and help on faster/discrete
GPUs where per-dispatch overhead is proportionally larger.
Everything else runs on the CPU, already fast via the verifier and multi-hash mode.

## Multi-hash mode (crack a whole dump at once)

Give `crack` a file of many hashes and Hashsmith automatically switches to
**multi-hash mode**: each candidate is hashed **once** and checked against every
target, instead of re-running the attack per hash. Cracking N hashes of the same
salt-independent raw-digest type (MD5, SHA-1/256/512, SHA-3, NTLM, RIPEMD-160,
Whirlpool, Streebog, BLAKE2, MySQL, MSSQL-2000 …) costs one keyspace pass, not N —
an N-fold reduction in work.

```bash
hashsmith crack -t md5 dump.txt -w rockyou.txt   # one pass finds every match
hashsmith crack dump.txt -w rockyou.txt          # auto-detect + multi-hash
```

Output pairs each hash with its plaintext:

```
⚡ Multi-hash mode: 5000 target(s), hashing each candidate once against all
  5f4dcc3b5aa765d61d8327deb882cf99  =>  password
  21232f297a57a5a743894a0e4a801fc3  =>  admin
  ...
```

Salted or expensive hashes in the same file (bcrypt, crypt(3), PBKDF2,
containers, network captures) are automatically split out and cracked
individually, since a per-target salt makes shared work impossible.

## Potfile & resumable sessions

Every cracked hash is recorded in a **potfile** (`~/.hashsmith/hashsmith.pot`)
so later runs skip work already done:

```bash
hashsmith crack -t md5 <hash>            # cracks it and records hash → plaintext
hashsmith crack -t md5 <hash>            # instantly reported from the potfile
hashsmith crack -t md5 <hash> --show     # print the potfile plaintext; never attack
hashsmith crack -t md5 <hash> --no-pot   # ignore the potfile (always attack, don't record)
hashsmith crack -t md5 <hash> --pot my.pot   # use a custom potfile path
```

Long keyspace runs — **brute, mask, markov, hybrid, and combinator** — can be
**checkpointed and resumed**. Name a run with `--session`; if it is interrupted
(Ctrl-C), its progress is saved and `--restore` picks up exactly where it
stopped:

```bash
hashsmith crack -t md5 <hash> -M brute -C ?a -n 1 -x 8 --session bigrun
# ^C  → "Interrupted — session "bigrun" saved at index 4153344/308915776"
hashsmith crack -t md5 <hash> -M brute -C ?a -n 1 -x 8 --restore bigrun   # resumes

hashsmith sessions                 # list saved sessions and their progress
hashsmith sessions rm bigrun       # delete one
hashsmith sessions clear           # delete all
```

A finished run (found or keyspace exhausted) removes its own session file.

## Commands

- `encode`
- `decode`
- `hash`
- `crack`
- `identify`
- `extractors`

### File → hash extractors (`*2smith`)

Turn a password-protected file into a crackable hash, then feed it straight to `crack`:

The binary currently contains **47 registry-backed extractors**. Run
`hashsmith extractors` for the authoritative list generated from that same
registry; command routing and help do not maintain separate copies.

| Family | Commands | Inputs / output formats |
|---|---|---|
| Archives and documents | `zip2smith`, `7z2smith`, `rar2smith`, `pdf2smith`, `office2smith` | ZipCrypto/WinZip AES, 7-Zip AES, RAR3/4/5, PDF RC4/AES, Office 2007–2013+ |
| Keys and encrypted stores | `ssh2smith`, `gpg2smith`, `pfx2smith`, `keepass2smith`, `pwsafe2smith`, `1password2smith` | OpenSSH/PEM/PKCS#8, OpenPGP, PKCS#12, KeePass 3/4, Password Safe 3, 1Password Agile Keychain |
| Full-disk/container | `luks2smith`, `truecrypt2smith`, `veracrypt2smith`, `bitlocker2smith`, `encfs2smith`, `dmg2smith` | LUKS1, TrueCrypt/VeraCrypt headers, BitLocker VMKs, EncFS 6, encrypted DMG v1/v2 |
| Wallets and backups | `ethereum2smith`, `electrum2smith`, `blockchain2smith`, `bitcoin2smith`, `monero2smith`, `multibit2smith`, `itunes2smith`, `androidbackup2smith` | Web3, Electrum, Blockchain.com, Bitcoin Core SQLite and legacy Berkeley DB, Monero `.keys`, MultiBit, iOS and Android backups |
| Application stores and VMs | `applenotes2smith`, `lastpass2smith`, `mozilla2smith`, `bitwarden2smith`, `signal2smith`, `telegram2smith`, `keychain2smith`, `vmx2smith`, `virtualbox2smith` | Apple Secure Notes, LastPass CLI, Mozilla/NSS, Bitwarden browser LevelDB/JSON and Android XML, Signal legacy preferences, Telegram Android/Desktop, legacy macOS Keychain, VMware and VirtualBox |
| Operating systems/directories | `shadow2smith`, `aix2smith`, `ldif2smith`, `htpasswd2smith`, `hashdump2smith` | Unix shadow, AIX security/passwd, LDAP LDIF, Apache htpasswd, pwdump/secretsdump/NTDS |
| Network/authentication | `hccapx2smith`, `ike2smith`, `sip2smith`, `vncpcap2smith`, `prosody2smith`, `aruba2smith` | WPA hccapx v4, IKE-PSK, SIP digest, PCAP/PCAPNG RFB/VNC authentication, XMPP SCRAM, ArubaOS |
| Universal ingestion | `scan2smith` | Finds every already-recognizable Hashsmith record in logs, configuration and arbitrary text |

The John-compatible additions are independent native-Go implementations. They
were behavior-audited against John jumbo rather than copied source-for-source,
which keeps Hashsmith's MIT licensing intact and removes the Python/Perl runtime
dependency.

Every extractor above emits a record that the same Hashsmith binary can detect
and verify. The DMG v1/v2, Monero CryptoNight-v0 + ChaCha8/20, Signal, Telegram
Desktop, legacy Keychain, and VNC paths are checked against published John
vectors. `bitcoin2smith` handles both modern Bitcoin Core SQLite wallets and
legacy Berkeley DB `wallet.dat` master-key records without a Berkeley DB runtime.

`bitwarden2smith` is the meaningful Chromium workflow: it reads the Bitwarden
extension's LevelDB and extracts a real master-password verifier. Chromium's own
`Login Data` passwords are protected by the operating-system key store and do
not expose a universal user-password hash, so Hashsmith does not advertise a
misleading `chromium2smith` label. For Wireshark captures, `vncpcap2smith`
accepts both PCAP and PCAPNG and emits the standard `$vnc$` record.

```bash
hashsmith ssh2smith -f id_ed25519 -o hash.txt   # extract
hashsmith hash.txt                               # auto-detect type & crack
```

### System password hashes

`shadow2smith` turns an `/etc/shadow` file — optionally merged with `/etc/passwd`
— into one crackable `user:hash` line per account. Locked/disabled accounts (`*`,
`!`, `!!`) are skipped, and recognised-but-unsupported schemes (e.g. yescrypt
`$y$`) are reported rather than silently dropped.

```bash
hashsmith shadow2smith shadow.txt passwd.txt -o hashes.txt   # just pass the files
hashsmith shadow2smith passwd.txt shadow.txt -o hashes.txt   # order doesn't matter
hashsmith shadow2smith shadow.txt -o hashes.txt              # shadow alone
hashsmith hashes.txt                                         # auto-detect crypt type & crack
```

No `-f`/`-p` is required — pass the files directly in **either order**. The tool
inspects each file's contents and decides which is the shadow file and which is
passwd on its own (classification is by content, not filename), then prints its
decision. Force a role with `-f`/`-p` only if you need to override the
auto-detection. Run `hashsmith shadow2smith -h` for the full command reference.

You can also crack a `user:hash` line — or a raw shadow entry — directly; the
leading username is detected and stripped automatically.

| `-t` type | Shadow prefix | Notes |
|---|---|---|
| `md5crypt`    | `$1$`  | MD5 crypt |
| `sha256crypt` | `$5$`  | SHA-256 crypt |
| `sha512crypt` | `$6$`  | SHA-512 crypt |
| `bcrypt`      | `$2a$` / `$2b$` / `$2y$` | Blowfish crypt |
| `descrypt`    | 13-char (no prefix) | traditional DES crypt |

### Network-capture hash types

These are captured as text — paste the line straight into `crack` (auto-detected):

| `-t` type | Source |
|---|---|
| `netntlmv1` | NetNTLMv1 / NTLMv1-ESS challenge-response |
| `netntlmv2` | NetNTLMv2 challenge-response |
| `krb5asrep` | Kerberos AS-REP roasting (etype 23 / RC4) |
| `krb5tgs`   | Kerberoasting TGS-REP (etype 23 / RC4) |

```bash
hashsmith 'admin::WORKGROUP:1122334455667788:9a94e588…:0101…'   # auto-detect & crack
```

### Encrypted-container hash types

Extracted with a `*2smith` command and cracked with the built-in wordlist:

| `-t` type | Notes |
|---|---|
| `ssh`     | OpenSSH, legacy PEM, and `$sshng$` records from `ssh2john`; DES/3DES/AES |
| `pkcs8`   | PKCS#8 PBES2 private keys (via `ssh2smith`) |
| `gpg`     | `gpg -c` symmetric messages and protected secret-key records from `gpg2john`; AES/CAST5/3DES |
| `office`  | MS Office 2007 (standard), 2010 (standard), 2013 (agile) |
| `keepass` | KeePass KDBX 1, 2 (AES-KDF) and 4 (Argon2d / Argon2id) |

Use help:
```bash
hashsmith --help
```

## How Hashsmith compares to Hashcat and John the Ripper

The three tools solve overlapping problems from different directions. Hashcat is
a GPU cracking engine, John the Ripper is a CPU cracking engine with an enormous
format library and a script ecosystem around it, and Hashsmith is a single
self-contained binary that tries to make the common path short.

| | Hashsmith | Hashcat | John the Ripper (jumbo) |
|---|---|---|---|
| Universal hash/code formats | 457 | 450+ native hash types | hundreds of native formats |
| Hash-type auto-detection | yes, by default | yes in Hashcat 7.x; `--identify` lists possibilities | yes for recognizable ciphertexts; first matching format wins |
| Accepted type vocabulary | 1,163 names/codes resolving into those same 457 formats, including 503 numeric Hashcat aliases | native numeric modes | native format labels |
| Attack modes | dict, brute, mask, markov, hybrid, combinator | straight, combinator, mask, hybrid, association | wordlist, incremental, mask, external |
| Rule engine | ~35 operators | full, on-GPU, the de-facto standard | full, plus C-like external mode |
| GPU | experimental, opt-in Metal/OpenCL; MD5 dictionary/rules plus MD5, MD4, NTLM, SHA-1, SHA-256 brute/mask/multi-target | mature CUDA / HIP / OpenCL / Metal across nearly every mode | OpenCL for a subset |
| File → hash extractors | **47**, native and built into one registry/binary | dedicated converters in the official `tools/` tree | a much broader `run/*2john` script collection plus compiled converters |
| Install | one static binary, no runtime deps | binary + GPU runtime | build or distro package + Perl/Python for extractors |
| Built-in known-answer self-test | `hashsmith selftest`, 502 vectors over all 457 formats, provenance-labelled | internal, on startup | `john --test` |
| Distributed cracking | no | via third-party overlays | via MPI |

**Where Hashsmith is the better tool.** You get one binary with no runtime
dependencies, hash extraction and cracking in the same place, and a universal
registry that keeps canonical names, aliases, descriptions, vectors, and test
policy synchronized. Its 47 integrated extractors cover workflows that Hashcat
generally leaves to separate utilities, while John still has the broader long-tail
extractor ecosystem. It also speaks both of the other tools' dialects, so a mode
number pasted from a Hashcat writeup or a `--format` label from a John tutorial
both work unchanged:

```bash
hashsmith crack -t 22300 '<sha256>:<salt>'      # Hashcat mode number
hashsmith crack -t john:dynamic_12 '<md5>:<salt>'  # John dynamic format
hashsmith crack -w rockyou.txt '<any hash>'     # or just let detection decide
```

**Verifying your own build.** `hashsmith selftest` runs the known-answer vectors
compiled into the binary, which answers a question a version number cannot: is
this copy, built by this toolchain, still computing the right answers? A
miscompilation, a bad optimisation or a corrupted download shows up here and
nowhere else.

```bash
hashsmith selftest              # 355 fast vectors
hashsmith selftest -slow        # include the high-iteration KDFs
hashsmith selftest -gaps        # list the types that have no vector yet
```

Each vector records where its expected value came from, because that changes
what a pass is worth — `published` (from the algorithm's specification or
reference suite), `cross-checked` (computed independently with Python or
OpenSSL) and `regression` (produced by Hashsmith itself, which catches drift but
cannot prove the implementation was right to begin with). The summary reports
the three separately rather than flattening them into one reassuring number, and
tells you honestly how many universal formats have no vector at all. All 457
formats now carry one: 371 published vectors, 112 independently cross-checked
vectors, and 19 regression-only vectors (502 total).

**Where they are the better tool.** For a large wordlist against a fast hash on
a real GPU, Hashcat will beat Hashsmith by orders of magnitude — its kernels are
mature and cover essentially every mode, while Hashsmith's GPU support is
experimental and implemented for only a handful of algorithms. If the format you
need is exotic — Lotus Domino, RACF, Android FDE, or many long-tail
cryptocurrency wallets — John's format library and its `*2john` scripts are far
broader. Neither of those gaps is close to being closed here, and picking the
right tool for the job beats loyalty to any one of them.

## Security Notice

Hashsmith is for educational and authorized security testing only.

## License

See [LICENSE](LICENSE).
