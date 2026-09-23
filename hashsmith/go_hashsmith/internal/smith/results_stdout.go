package smith

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// ── Machine-readable results on stdout ────────────────────────────────────────
//
// Every cracked target is written to STDOUT as one `hash:plaintext` line, while
// the banner, progress bar, status lines and colour stay on STDERR.
//
// Before this, `crack` wrote nothing whatsoever to stdout — it was the only
// command in the tool whose results could not be piped or redirected, so
// `hashsmith crack ... > found.txt` produced an empty file while the terminal
// showed the password. Splitting the streams is what makes the command
// composable, and it costs the interactive user nothing: a terminal shows both.

// hexWrapPlaintext renders a recovered plaintext for a `hash:plaintext` line.
//
// A plaintext may legitimately contain the ':' separator, a newline, or bytes
// that are not printable at all, any of which makes the line ambiguous or
// unparseable. Hashcat solves this with the $HEX[...] wrapper and so do we, so
// that a consumer can always split on the LAST ':' and know what it has.
func hexWrapPlaintext(pw string) string {
	needsHex := pw == "" || strings.ContainsAny(pw, ":\r\n\t") ||
		strings.TrimSpace(pw) != pw
	if !needsHex {
		for i := 0; i < len(pw); i++ {
			if pw[i] < 0x20 || pw[i] == 0x7f {
				needsHex = true
				break
			}
		}
	}
	if needsHex {
		return "$HEX[" + hex.EncodeToString([]byte(pw)) + "]"
	}
	return pw
}

// emitStdoutResult writes one cracked target to stdout in `hash:plaintext`
// form. It is called in addition to the existing human-facing stderr output,
// never instead of it.
//
// Under --left, stdout is already reserved for the list of targets that were
// NOT cracked, so nothing is written there — the same rule emitResult applies
// to -o, kept consistent so the two output paths never disagree about who owns
// the stream.
func emitStdoutResult(cc *crackCtx, hash, plaintext string) {
	if cc != nil && cc.left {
		return
	}
	fmt.Fprintf(os.Stdout, "%s:%s\n", hash, hexWrapPlaintext(plaintext))
}
