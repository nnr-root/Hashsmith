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
```

Shortcut:
```bash
hashsmith -id -i "aGVsbG8="
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
