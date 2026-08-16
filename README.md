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

## Commands

- `encode`
- `decode`
- `hash`
- `crack`
- `identify`

Use help:
```bash
hashsmith --help
```

## Security Notice

Hashsmith is for educational and authorized security testing only.

## License

See [LICENSE](LICENSE).
