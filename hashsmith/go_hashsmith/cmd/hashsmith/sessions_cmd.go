package main

// `hashsmith sessions` inspects and manages saved brute/mask sessions stored
// under ~/.hashsmith/sessions. Resume one with `crack --restore <name>`.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runSessions(args []string) error {
	sub := "list"
	var rest []string
	if len(args) > 0 {
		sub, rest = strings.ToLower(args[0]), args[1:]
	}
	switch sub {
	case "list", "ls":
		return listSessions()
	case "rm", "delete", "remove":
		if len(rest) == 0 {
			return fmt.Errorf("usage: hashsmith sessions rm <name>")
		}
		for _, name := range rest {
			if err := os.Remove(sessionPath(name)); err != nil {
				clrYellow.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			} else {
				clrGreen.Fprintf(os.Stderr, "  removed %s\n", name)
			}
		}
		return nil
	case "clear":
		entries, _ := filepath.Glob(filepath.Join(sessionsDir(), "*.json"))
		for _, e := range entries {
			_ = os.Remove(e)
		}
		clrGreen.Fprintf(os.Stderr, "Cleared %d session(s)\n", len(entries))
		return nil
	default:
		return fmt.Errorf("unknown sessions subcommand %q (use: list | rm <name> | clear)", sub)
	}
}

func listSessions() error {
	entries, _ := filepath.Glob(filepath.Join(sessionsDir(), "*.json"))
	if len(entries) == 0 {
		clrYellow.Fprintln(os.Stderr, "No saved sessions.")
		return nil
	}
	accentPrintln("Saved sessions (resume with: crack --restore <name>)")
	for _, e := range entries {
		name := strings.TrimSuffix(filepath.Base(e), ".json")
		s, err := loadSession(name)
		if err != nil || s == nil {
			fmt.Printf("  %-16s (unreadable)\n", name)
			continue
		}
		pct := 0.0
		if s.Total > 0 {
			pct = float64(s.Checkpoint) / float64(s.Total) * 100
		}
		desc := s.Mode + "/" + s.Type
		if s.Mask != "" {
			desc += " " + s.Mask
		}
		fmt.Printf("  %-16s %-22s %5.1f%%  (%d/%d)  %s\n",
			name, desc, pct, s.Checkpoint, s.Total, s.Updated)
	}
	return nil
}
