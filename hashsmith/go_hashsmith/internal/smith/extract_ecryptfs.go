package smith

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ecryptfs2smith reads an eCryptfs wrapped-passphrase file and writes the
// record Hashsmith and hashcat -m 12200 crack.
//
// The file is tiny and has two shapes, told apart by its first two bytes:
//
//	":\x02"  version 2 — then 8 raw bytes of salt, then 16 ASCII hex of signature
//	anything version 1 — those two bytes ARE the start of 16 ASCII hex, and the
//	                     salt lives outside the file
//
// Version 1's salt comes from the user's ~/.ecryptfsrc, or from eCryptfs's
// built-in default when there is no such file. ecryptfs2john takes that path
// as a second argument and quietly emits the unsalted record when you forget
// it; this looks for it instead, so the common layout needs no second
// argument. When none is found the short record is produced, which the
// verifier reads against the built-in salt.
func runExtractECryptfs(args []string) error {
	return runFileRecordExtractor("ecryptfs2smith", args, extractECryptfsRecords)
}

func extractECryptfsRecords(path string) ([]string, error) {
	raw, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("%s is %d bytes; a wrapped-passphrase is at least 16",
			filepath.Base(path), len(raw))
	}

	var saltHex, sig string
	if raw[0] == ':' && raw[1] == 0x02 {
		if len(raw) < 2+8+16 {
			return nil, errors.New("version-2 wrapped-passphrase is truncated")
		}
		saltHex = hex.EncodeToString(raw[2:10])
		sig = string(raw[10:26])
	} else {
		sig = string(raw[:16])
		// The salt may sit beside the file, which is where eCryptfs itself
		// puts a non-default one. Looking for it is worth doing: without it
		// the record falls back to the built-in salt, and a file wrapped with
		// a custom one would then never crack.
		if s, ok := findECryptfsRCSalt(filepath.Dir(path)); ok {
			saltHex = s
		}
	}

	if _, err := hex.DecodeString(sig); err != nil || len(sig) != 16 {
		return nil, fmt.Errorf("%s does not hold a 16-character hex signature where one belongs; "+
			"this is probably not a wrapped-passphrase file", filepath.Base(path))
	}
	if saltHex != "" {
		return []string{"$ecryptfs$0$1$" + saltHex + "$" + sig}, nil
	}
	return []string{"$ecryptfs$0$" + sig}, nil
}

// findECryptfsRCSalt looks for a salt= line in a .ecryptfsrc beside the
// wrapped-passphrase, and one directory up ONLY when the file sits in a
// directory named .ecryptfs — which is the layout eCryptfs actually creates,
// with ~/.ecryptfs/wrapped-passphrase beside ~/.ecryptfsrc.
//
// The restriction is not fussiness. Without it, a wrapped-passphrase copied
// anywhere under a home directory picked up that home's .ecryptfsrc and got a
// salt it was never wrapped with, which produces a record that looks more
// precise than the short one and cannot crack. Caught by extracting from a
// copy of the same file in a sibling directory and watching the salt follow
// it.
func findECryptfsRCSalt(dir string) (string, bool) {
	candidates := []string{filepath.Join(dir, ".ecryptfsrc")}
	if filepath.Base(dir) == ".ecryptfs" {
		candidates = append(candidates, filepath.Join(filepath.Dir(dir), ".ecryptfsrc"))
	}
	for _, candidate := range candidates {
		f, err := os.Open(candidate)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			rest, ok := strings.CutPrefix(line, "salt=")
			if !ok {
				continue
			}
			// eCryptfs uses a fixed-size salt, so a longer value is truncated
			// rather than rejected — which is what its own tooling does.
			if len(rest) > 16 {
				rest = rest[:16]
			}
			if _, err := hex.DecodeString(rest); err != nil || len(rest) != 16 {
				continue
			}
			f.Close()
			return rest, true
		}
		f.Close()
	}
	return "", false
}
