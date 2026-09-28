package smith

// Microsoft Money, BitShares, and Oracle PeopleSoft's PS_TOKEN cookie.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ── Microsoft Money ───────────────────────────────────────────────────────────

func runExtractMoney(args []string) error {
	return runFileRecordExtractor("money2smith", args, extractMoneyRecords)
}

// moneyHeaderMask is the fixed 132-byte pad Money XORs over its header. It is
// not a key and it is not derived from anything: the same bytes are in every
// installation, so the "obfuscation" it performs is undone by knowing them.
const moneyHeaderMask = "b56f03626108c255eba96772433f009c7a9f90ff809a31c579baed30bcdfcc9d" +
	"63d9e4c37b42fb8abc4e86fbec375d449cfac65e28e613b68a6054947b36f572" +
	"dfb177f41343cfafb1333461795b92b57c2a05f17c99011b98fd124f4a946c3e" +
	"60265f95f8d089248567c61f2744d2eecf65edff07c746a178160cede92d62d4"

// Offsets into the UNMASKED header.
const (
	moneyMaskAt      = 24
	moneySaltAt      = 0x72
	moneyCheckStart  = 0x2e9
	moneyFlagsAt     = 0x298
	moneyFlagNew     = 0x06 // the file uses the hashing scheme at all
	moneyFlagSHA1    = 0x20 // ... with SHA-1 rather than MD5
	moneyHeaderBytes = 4096
)

// extractMoneyRecords reads a Money file's header.
//
// The check value's position is not fixed: it sits at a base offset plus the
// FIRST BYTE OF THE SALT, so the file's own salt says where to find the thing
// the salt is used to check. Read it from the base offset alone and the record
// carries four bytes of something else, which is a record that parses and
// never cracks.
func extractMoneyRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, moneyHeaderBytes)
	n, _ := io.ReadFull(f, buf)
	if n < moneyCheckStart+0x100 {
		return nil, errors.New("this file is shorter than a Money header")
	}
	buf = buf[:n]

	mask, err := hex.DecodeString(moneyHeaderMask)
	if err != nil {
		return nil, err
	}
	for i, m := range mask {
		if moneyMaskAt+i < len(buf) {
			buf[moneyMaskAt+i] ^= m
		}
	}

	flags := buf[moneyFlagsAt]
	if flags&moneyFlagNew == 0 {
		return nil, errors.New("this Money file is not encrypted")
	}
	salt := buf[moneySaltAt : moneySaltAt+8]
	// The first salt byte is also an offset. See the note above.
	checkAt := moneyCheckStart + int(salt[0])
	if checkAt+4 > len(buf) {
		return nil, errors.New("this Money file's check value lies past the header")
	}
	kind := 0
	if flags&moneyFlagSHA1 != 0 {
		kind = 1
	}
	if kind == 0 {
		fmt.Fprintln(os.Stderr, "note: this is an older Money file, which keys with MD5 rather than SHA-1")
	}
	return []string{fmt.Sprintf("$money$%d*%s*%s", kind,
		hex.EncodeToString(salt), hex.EncodeToString(buf[checkAt:checkAt+4]))}, nil
}

// ── BitShares ─────────────────────────────────────────────────────────────────

func runExtractBitShares(args []string) error {
	return runFileRecordExtractor("bitshares2smith", args, extractBitSharesRecords)
}

// extractBitSharesRecords reads a BitShares wallet in whichever of its three
// shapes it is in.
//
// The SQLite wallet and the LevelDB one both yield a record that can be
// checked. The BACKUP file does not: its record wraps a secp256k1 key, and
// nothing in it can say whether a password was right without doing elliptic
// curve arithmetic this tool does not do. John writes such a record anyway;
// this names the problem instead, because a record that cannot be checked is
// not a record worth handing back.
func extractBitSharesRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// LevelDB: the key material follows the literal word "checksum" plus
	// three bytes of its own framing. John scans for it rather than
	// reading the log properly, and so does this — the alternative is a
	// LevelDB reader for one field.
	if i := bytes.Index(data, []byte("checksum")); i >= 0 {
		start := i + len("checksum") + 3
		if start+128 <= len(data) {
			if field := string(data[start : start+128]); isHex(field) {
				return []string{"$dynamic_84$" + strings.ToLower(field)}, nil
			}
		}
	}

	if records, err := extractBitSharesSQLite(path); err == nil && len(records) > 0 {
		return records, nil
	}

	if bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		return nil, errors.New("this SQLite wallet has no row carrying an encryption_key")
	}
	return nil, errors.New("this looks like a BitShares backup file, whose record wraps a secp256k1 key: nothing in it can say whether a password was right without elliptic-curve arithmetic, so no record is written for it")
}

func extractBitSharesSQLite(path string) ([]string, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT key, value FROM wallet")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []string
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		var entry struct {
			EncryptionKey string `json:"encryption_key"`
		}
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}
		// Only the LAST thirty-two bytes are the record: the field
		// carries the IV and the block before it too.
		if len(entry.EncryptionKey) < 64 {
			continue
		}
		records = append(records, "$BitShares$0*"+entry.EncryptionKey[len(entry.EncryptionKey)-64:])
	}
	return records, rows.Err()
}

// ── Oracle PeopleSoft PS_TOKEN ────────────────────────────────────────────────

func runExtractPSToken(args []string) error {
	return runFileRecordExtractor("ps_token2smith", args, extractPSTokenRecords)
}

const (
	psTokenMACAt   = 44
	psTokenMACLen  = 20
	psTokenDataAt  = 76
	psTokenMinSize = psTokenDataAt + 8
)

// extractPSTokenRecords reads PeopleSoft's PS_TOKEN cookie.
//
// The cookie is base64 and what it carries is DEFLATE-compressed, so the salt
// the record needs does not appear anywhere in the cookie as written: it has
// to be decompressed out of it. The digest is SHA-1 over that decompressed
// data followed by the password as UTF-16LE.
//
// One case is not a crackable record and is reported instead: when the SHA-1
// of the data equals the stored MAC, the node has NO password at all — the
// token is signed with the empty key — and there is nothing to find.
//
// John takes the cookie as a command-line argument. Here it is read from a
// file, one token per line, because that is what the rest of these converters
// take and because a cookie is long enough that pasting it into a shell is how
// it gets truncated.
func extractPSTokenRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	unsigned := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(raw) < psTokenMinSize {
			continue
		}
		mac := raw[psTokenMACAt : psTokenMACAt+psTokenMACLen]

		zr, err := zlib.NewReader(bytes.NewReader(raw[psTokenDataAt:]))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(zr, 1<<20))
		zr.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		sum := sha1.Sum(data)
		if bytes.Equal(sum[:], mac) {
			unsigned++
			continue
		}
		// dynamic_1600 is sha1($s.utf16le($p)); the decompressed token
		// is the salt.
		records = append(records, fmt.Sprintf("$dynamic_1600$%s$HEX$%s",
			hex.EncodeToString(mac), hex.EncodeToString(data)))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		if unsigned > 0 {
			return nil, fmt.Errorf("%d token(s) read, and every one is signed with an empty key: those nodes have no password to find", unsigned)
		}
		return nil, errors.New("no PS_TOKEN cookies found; each line should be one base64 cookie value")
	}
	return records, nil
}
