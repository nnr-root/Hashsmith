package smith

import "fmt"

// coordinatorKeyspace computes the total candidate count for the
// coordinate command's chosen mode, reusing the exact same layout
// construction the normal (single-machine) crack path already uses
// internally — see keyspace.go's maskLayout/bruteLayout and crack.go's
// exactWordlistCount. This guarantees the coordinator's chunking is
// counting in the same units --skip/--limit already use everywhere else
// in this project.
func coordinatorKeyspace(mode, mask, cs1, cs2, cs3, cs4, charset string, minLen, maxLen int, wordlist string) (int64, error) {
	switch mode {
	case "mask":
		mc := buildMaskConfig(mask, cs1, cs2, cs3, cs4, false, 0, false)
		layout, err := maskLayout(mc)
		if err != nil {
			return 0, err
		}
		return layout.total, nil
	case "brute":
		layout := bruteLayout(charset, minLen, maxLen)
		return layout.total, nil
	case "dict":
		return exactWordlistCount(wordlist)
	default:
		return 0, fmt.Errorf("unknown mode %q: use mask, brute, or dict", mode)
	}
}
