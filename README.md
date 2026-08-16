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

```bash
hashsmith encode -t base64 -i "hello"
hashsmith decode -t base64 -i "aGVsbG8="
hashsmith hash -t sha256 -i "secret"
hashsmith crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99          # uses the built-in common.txt wordlist
hashsmith crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99 -w custom.txt   # or supply your own with -w / --wordlist
hashsmith identify -i "aGVsbG8="
hashsmith identify -i hash.txt          # -i also accepts a file (one hash per line)
```

Auto-detect & crack (John-the-Ripper style) — no need to name the hash type:
```bash
hashsmith 5f4dcc3b5aa765d61d8327deb882cf99   # detects the type, then cracks it
hashsmith hashes.txt                          # cracks every hash in a file (one per line)
hashsmith crack -H 5f4dcc3b5aa765d61d8327deb882cf99   # same auto-detection via the crack command
```
When the type is ambiguous (e.g. a 32-char hex could be MD5/MD4/NTLM) every candidate is tried in turn.
Specifying `-t <type>` skips detection and is faster.

Identify shortcut — `-i` takes an inline value (in `'…'` or `"…"`) or a file path:
```bash
hashsmith -i "aGVsbG8="
hashsmith -i hash.txt
```

Flexible arguments — flag order doesn't matter and every flag form is accepted:
```bash
hashsmith -w=rockyou.txt hash.txt        # flags first
hashsmith hash.txt -w rockyou.txt        # target first
hashsmith hash.txt --wordlist=rockyou.txt
hashsmith hash.txt --wordlist rockyou.txt
```
`-w x`, `-w=x`, `--wordlist x`, and `--wordlist=x` are all equivalent, and the
hash/file target may appear anywhere among the flags.

## Commands

- `encode`
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

```bash
hashsmith ssh2smith -f id_ed25519 -o hash.txt   # extract
hashsmith hash.txt                               # auto-detect type & crack
```

### Network-capture hash types

These are captured as text (Responder, impacket, Rubeus) — paste the line straight into `crack` (auto-detected):

| `-t` type | hashcat | Source |
|---|---|---|
| `netntlmv1` | 5500 | NetNTLMv1 / NTLMv1-ESS challenge-response |
| `netntlmv2` | 5600 | NetNTLMv2 challenge-response |
| `krb5asrep` | 18200 | Kerberos AS-REP roasting (etype 23 / RC4) |
| `krb5tgs`   | 13100 | Kerberoasting TGS-REP (etype 23 / RC4) |

```bash
hashsmith 'admin::WORKGROUP:1122334455667788:9a94e588…:0101…'   # auto-detect & crack
```

### Encrypted-container hash types

Extracted with a `*2smith` command (or pasted from hashcat/john) and cracked with the built-in wordlist:

| `-t` type | hashcat | Notes |
|---|---|---|
| `pkcs8`   | –     | PKCS#8 PBES2 private keys (via `ssh2smith`) |
| `gpg`     | 16700/17010 | `gpg -c` symmetric (via `gpg2smith`); AES-128/192/256 |
| `office`  | 9400/9500/9600 | MS Office 2007 (standard), 2010 (standard), 2013 (agile) |
| `keepass` | 13400 | KeePass KDBX 1, 2 (AES-KDF) and 4 (Argon2d / Argon2id) |

Use help:
```bash
hashsmith --help
```

## Security Notice

Hashsmith is for educational and authorized security testing only.

## License

See [LICENSE](LICENSE).
