package main

import "github.com/atotto/clipboard"

func copyToClipboard(text string) bool {
	return clipboard.WriteAll(text) == nil
}
