package smith

import "github.com/atotto/clipboard"

func copyToClipboard(text string) bool {
	return clipboard.WriteAll(text) == nil
}
