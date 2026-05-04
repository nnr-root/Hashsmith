package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	themeAttr = color.FgCyan
	noBanner  bool
)

var themeMap = map[string]color.Attribute{
	"cyan":    color.FgCyan,
	"green":   color.FgGreen,
	"magenta": color.FgMagenta,
	"blue":    color.FgBlue,
	"yellow":  color.FgYellow,
	"red":     color.FgRed,
	"white":   color.FgWhite,
}

func setTheme(name string) {
	if attr, ok := themeMap[name]; ok {
		themeAttr = attr
	} else {
		themeAttr = color.FgCyan
	}
}

func accentSprint(s string) string     { return color.New(themeAttr).Sprint(s) }
func boldAccentSprint(s string) string { return color.New(themeAttr, color.Bold).Sprint(s) }

var (
	clrGreen  = color.New(color.FgGreen, color.Bold)
	clrYellow = color.New(color.FgYellow)
	clrRed    = color.New(color.FgRed, color.Bold)
)

var bannerArt = []string{
	" _   _           _     ____            _ _   _     ",
	"| | | | __ _ ___| |__ / ___| _ __ ___ (_) |_| |__  ",
	"| |_| |/ _` / __| '_ \\\\___ \\| '_ ` _ \\| | __| '_ \\ ",
	"|  _  | (_| \\__ \\ | | |___) | | | | | | | |_| | | |",
	"|_| |_|\\__,_|___/_| |_|____/|_| |_| |_|_|\\__|_| |_|",
}

func renderBanner() {
	if noBanner {
		return
	}
	extra := []string{"", "Hashsmith", "Modular Forensic & Cryptography Toolkit"}
	all := append(append([]string{}, bannerArt...), extra...)

	maxW := 0
	for _, l := range all {
		if len(l) > maxW {
			maxW = len(l)
		}
	}
	boxW := maxW + 2

	border := color.New(themeAttr).Sprint
	bold := color.New(themeAttr, color.Bold).Sprint

	fmt.Fprintf(os.Stderr, "%s\n", border("╭"+strings.Repeat("─", boxW)+"╮"))
	for i, line := range all {
		pad := strings.Repeat(" ", maxW-len(line))
		content := " " + line + pad + " "
		var styled string
		switch {
		case i < len(bannerArt):
			styled = border(content)
		case line == "Hashsmith":
			styled = bold(content)
		default:
			styled = content
		}
		fmt.Fprintf(os.Stderr, "%s%s%s\n", border("│"), styled, border("│"))
	}
	fmt.Fprintf(os.Stderr, "%s\n", border("╰"+strings.Repeat("─", boxW)+"╯"))
}

func outputResult(result, outFile string, copyResult bool) error {
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(result+"\n"), 0644); err != nil {
			return err
		}
		clrGreen.Fprintf(os.Stderr, "Saved to %s\n", outFile)
	} else {
		fmt.Println(result)
	}
	if copyResult {
		if copyToClipboard(result) {
			clrGreen.Fprintln(os.Stderr, "Copied to clipboard")
		} else {
			clrYellow.Fprintln(os.Stderr, "Unable to copy to clipboard")
		}
	}
	return nil
}

func readInput(text, filePath string) (string, error) {
	if text != "" {
		return text, nil
	}
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", errors.New("provide -i text or -f file path")
}
