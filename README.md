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
Specifying `-t <type>` skips detection and is faster.

Identify shortcut — `-i` takes an inline value (in `'…'` or `"…"`), a comma-list, or a file path:
```bash
hashsmith -i "aGVsbG8="
hashsmith -i hash.txt
```

> Multi-input is comma-separated, so a single input that itself contains a comma should be given via a file (one line).

### Hash types

Hashsmith supports **100+ hash types**, and every one is validated against a
known-answer vector before shipping — no unimplemented stubs, no unvalidated
crypto. Most hashes are auto-detected, so naming a type is optional. When you want
to pin one, pass `-t <name>`; run `hashsmith types` for the full catalogue. Beyond
the raw digests, Hashsmith covers salted placements, nested digests, and HMAC
natively:

```bash
hashsmith crack -t md5 <hash> -s 12345678 -S suffix   # md5($pass . $salt)
hashsmith crack -t md5 <hash> -s 12345678 -S prefix   # md5($salt . $pass)
hashsmith crack -t md5-md5 <hash>                     # md5(hex(md5($pass)))
hashsmith crack -t hmac-sha256 <hash>:<salt>          # HMAC-SHA256, key = password
hashsmith crack -t hmac-sha256-saltkey <hash>:<salt>  # HMAC-SHA256, key = salt
hashsmith types                                       # list every supported -t type
```

Covered today: the full **raw / salted / iterated / HMAC** digest family
(MD4/MD5/SHA1/SHA2/SHA3/RIPEMD-160/BLAKE2b/BLAKE2s, salted with `-s`/`-S`, the
`digest-digest` nested forms, and HMAC in both key-modes), the Unix crypt(3)
family (`descrypt`/`md5crypt`/`sha256crypt`/`sha512crypt`/`bcrypt`), MySQL, MSSQL,
PostgreSQL, NTLM/NetNTLM, Kerberos, Argon2/scrypt, generic PBKDF2, and every
encrypted-container format handled by the `*2smith` extractors.

Application, device & framework hashes: **Django**, **phpass** (WordPress/phpBB3),
**Drupal 7**, **MediaWiki**, **vBulletin**, **Redmine**, **LDAP** (`{SSHA*}`/`{SMD5}`),
**Cisco-IOS 8/9**, **Cisco-PIX/ASA**, **Citrix NetScaler**, **Juniper NetScreen**,
**macOS 10.8+** (`$ml$`), **Atlassian** (`{PKCS5S2}`), **JWT** (HMAC), **SIP digest**,
**SolarWinds Orion**, and **Bitwarden** — all vector-tested.

Database, auth & directory hashes: **MySQL**, **MSSQL**, **PostgreSQL** (incl.
**SCRAM-SHA-256**), **MongoDB SCRAM-SHA-1**, **Sybase ASE**, **SAP CODVN B & F/G**,
**NTLM/NetNTLM**, **Kerberos**, Active Directory **DCC/DCC2** (mscash/mscash2),
**CRAM-MD5**, **IPMI2 RAKP**, and **iSCSI CHAP** — all vector-tested.

### Wireless, wallets & disk encryption

Every entry is validated against a known-answer vector before shipping (802.11i /
RFC 4493 for WPA, go-ethereum's keystore test data for Ethereum, the reference
wallet examples for Bitcoin/Electrum, real VeraCrypt/BitLocker/LUKS volumes):

| `-t` type | Format | Covers |
|---|---|---|
| `wpa` | `WPA*01*…` / `WPA*02*…` / `pmkid*ap*sta*essid` | WPA/WPA2 PMKID and EAPOL 4-way handshake (HMAC-MD5/SHA1, AES-CMAC) |
| `ethereum` | `$ethereum$p*…` / `$ethereum$s*…` | Web3/Geth keystore v3 (PBKDF2 and scrypt) |
| `bitcoin` | `$bitcoin$…` | Bitcoin/Litecoin wallet.dat (iterated SHA-512 + AES-256-CBC) |
| `electrum` | `$electrum$1*…` | Electrum wallet salt-type 1-3 (double SHA-256 + AES-CBC) |
| `veracrypt` / `truecrypt` | `veracrypt:<512-byte-header-hex>` | VeraCrypt/TrueCrypt — AES/Serpent/Twofish-XTS × SHA-512/SHA-256/Whirlpool/Streebog/RIPEMD-160 |
| `bitlocker` | `$bitlocker$…` | BitLocker (1M-round SHA-256 + AES-CTR VMK check) |
| `luks` | `$luks$…` (via `luks2smith`) | LUKS v1 — AES/Twofish/Serpent × XTS/CBC-ESSIV/CBC × SHA-1/256/512/RIPEMD-160/Whirlpool |
| `phpass` / `drupal7` | `$P$…` / `$H$…` / `$S$…` | WordPress, phpBB3, Drupal 7 |

```bash
hashsmith 'WPA*01*<pmkid>*<ap>*<sta>*<essid_hex>' -w wordlist.txt   # auto-detected
hashsmith '$ethereum$s*262144*1*8*<salt>*<ct>*<mac>' -w wordlist.txt
hashsmith '$bitcoin$96*…' -w wordlist.txt
hashsmith crack -t veracrypt 'veracrypt:<header-hex>' -w wordlist.txt
hashsmith luks2smith -f volume.luks -o luks.hash && hashsmith luks.hash -w wordlist.txt
```

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
```

**Mask placeholders:** `?l` a-z · `?u` A-Z · `?d` 0-9 · `?s` symbols · `?a` all
printable · `?h`/`?H` lower/upper hex · `?b` any byte. Define up to four custom
sets with `-1`…`-4` (referenced as `?1`…`?4`), escape a literal `?` as `\?`, and
any other character is a literal. `--increment` tries shorter lengths first.

```bash
hashsmith crack -t md5 <hash> -M mask --mask '?1?1?1?1' -1 '?l?d'   # 4 chars, each a-z or 0-9
hashsmith crack -t md5 <hash> -M mask --mask '?a?a?a?a' --increment # lengths 1..4
```

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

Long brute-force and mask runs can be **checkpointed and resumed**. Name a run
with `--session`; if it is interrupted (Ctrl-C), its progress is saved and
`--restore` picks up exactly where it stopped:

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
- `decode`
- `hash`
- `crack`
- `identify`

### File → hash extractors (`*2smith`)

Turn a password-protected file into a crackable hash, then feed it straight to `crack`:

| Command | Input | Formats |
|---|---|---|
| `zip2smith` | `.zip` | ZipCrypto, WinZip AES-128/192/256 |
| `7z2smith`  | `.7z`  | 7-Zip AES-256 |
| `rar2smith` | `.rar` | RAR3/RAR4 (`-hp`), RAR5 |
| `pdf2smith` | `.pdf` | Standard security handler (RC4 / AES) |
| `ssh2smith` | SSH / private key | OpenSSH (bcrypt-pbkdf + AES), legacy PEM (AES-CBC / 3DES), PKCS#8 PBES2 (PBKDF2) |
| `gpg2smith` | `.gpg` / `.asc` | `gpg -c` symmetric (AES-128/192/256, CAST5, 3DES) |
| `keepass2smith` | `.kdbx` | KeePass KDBX 3.1 (AES-KDF) and KDBX 4 (Argon2d / Argon2id) |
| `office2smith` | `.docx` / `.xlsx` / `.pptx` | MS Office 2007/2010 (standard) and 2013+ (agile) |
| `shadow2smith` | `/etc/shadow` (+ `/etc/passwd`) | Linux/Unix login hashes — extraction to `user:hash` |

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
| `pkcs8`   | PKCS#8 PBES2 private keys (via `ssh2smith`) |
| `gpg`     | `gpg -c` symmetric (via `gpg2smith`); AES-128/192/256 |
| `office`  | MS Office 2007 (standard), 2010 (standard), 2013 (agile) |
| `keepass` | KeePass KDBX 1, 2 (AES-KDF) and 4 (Argon2d / Argon2id) |

Use help:
```bash
hashsmith --help
```

## Security Notice

Hashsmith is for educational and authorized security testing only.

## License

See [LICENSE](LICENSE).
