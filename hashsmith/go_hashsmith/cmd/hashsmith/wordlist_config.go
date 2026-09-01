package main

// ── The persisted user default (~/.hashsmith/config.json) ────────────────────
//
// Auto-detection finds rockyou.txt where a distribution put it. It cannot know
// that this operator always wants /data/lists/corp-2024.txt, and pinning that
// through $HASHSMITH_WORDLIST means re-exporting it in every shell, every tmux
// pane and every cron entry. So the setting is written to disk once and read
// on every later run.
//
// Three decisions worth stating outright:
//
//  1. It lives in the directory the tool ALREADY owns — ~/.hashsmith, the same
//     one holding the potfile and saved sessions (hashsmithDir). A second
//     config location would mean two places to look when a run attacks the
//     wrong list, and "which of the two won?" is precisely the question an
//     operator should never have to ask.
//
//  2. The file is versioned JSON with an open shape, because this will not be
//     the only setting. An unknown field from a newer hashsmith is ignored
//     rather than fatal, so downgrading does not brick the tool.
//
//  3. It sits BELOW $HASHSMITH_WORDLIST in the resolution order (see
//     resolveWordlist). An explicit flag beats an environment variable beats a
//     setting saved months ago: the more recent and more deliberate the
//     statement of intent, the higher it ranks.
//
// Every failure mode here degrades to a warning and falls through, never to a
// panic and never to silently attacking a different list without saying so.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hashsmithConfigVersion is the schema version written to new files. It exists
// so a future incompatible change can be detected instead of misread; a file
// carrying a HIGHER version is still read on a best-effort basis, because the
// fields we understand are the fields we use.
const hashsmithConfigVersion = 1

// hashsmithConfig is the on-disk settings file. Every field is optional and
// omitempty, so the file stays small and a cleared setting leaves no
// misleading empty string behind for the next reader to interpret.
type hashsmithConfig struct {
	Version int `json:"version"`
	// Wordlist is the operator's pinned default, absolute. Empty means unset,
	// which is not the same as absent: both resolve to "no saved default", and
	// neither is an error.
	Wordlist string `json:"wordlist,omitempty"`
}

// hashsmithConfigPath returns the settings file path. It is a func var so
// tests can point it at a temp directory: a test that read the developer's
// real ~/.hashsmith/config.json would pass or fail depending on whose machine
// ran it, which is worth nothing.
var hashsmithConfigPath = defaultHashsmithConfigPath

// defaultHashsmithConfigPath is ~/.hashsmith/config.json — deliberately
// hashsmithDir(), the directory the potfile and sessions already live in.
func defaultHashsmithConfigPath() string {
	return filepath.Join(hashsmithDir(), "config.json")
}

// loadHashsmithConfig reads the settings file.
//
// A MISSING file is not an error: the overwhelmingly common case is an
// operator who has never run --set-default, and making them see an error for
// that would train them to ignore errors from this file. Anything else — an
// unreadable file, a directory where the file should be, malformed JSON — IS
// returned as an error, because at that point the tool genuinely does not know
// what the operator configured, and guessing is how you attack the wrong list.
// The caller (resolveWordlist) turns that error into a prominent warning and
// carries on with the next source, so a corrupt config never locks anyone out.
func loadHashsmithConfig() (hashsmithConfig, error) {
	path := hashsmithConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hashsmithConfig{}, nil
		}
		return hashsmithConfig{}, fmt.Errorf("cannot read %s: %w", path, err)
	}
	// An empty (or all-whitespace) file is treated as "no settings" rather
	// than as malformed JSON: a truncated write or a `> config.json` leaves
	// exactly this, and there is nothing ambiguous about what it means.
	if len(strings.TrimSpace(string(data))) == 0 {
		return hashsmithConfig{}, nil
	}
	var cfg hashsmithConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return hashsmithConfig{}, fmt.Errorf("%s is not valid JSON: %w "+
			"(fix it by hand, or run `hashsmith wordlists --clear-default` to rewrite it)", path, err)
	}
	return cfg, nil
}

// saveHashsmithConfig writes the settings file, creating ~/.hashsmith if
// needed. It writes to a temp file in the same directory and renames, so an
// interrupted write cannot leave a half-written config that the next run
// rejects as malformed.
//
// The file is 0600 and the directory 0700: it names a path on this machine and
// nothing else needs to read it.
func saveHashsmithConfig(cfg hashsmithConfig) error {
	cfg.Version = hashsmithConfigVersion
	path := hashsmithConfigPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the settings directory %s: %w "+
			"(the setting was NOT saved)", dir, err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode settings: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, "config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("cannot write in the settings directory %s: %w "+
			"(the setting was NOT saved)", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("cannot write %s: %w (the setting was NOT saved)", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot write %s: %w (the setting was NOT saved)", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot set permissions on %s: %w (the setting was NOT saved)", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot replace %s: %w (the setting was NOT saved)", path, err)
	}
	return nil
}

// savedWordlistDefault returns the pinned default, or "" when none is set. The
// error is a CONFIG error (unreadable, malformed) — never "the file does not
// exist" and never "the pinned file is missing", which the caller handles
// separately because the two have different remedies.
func savedWordlistDefault() (string, error) {
	cfg, err := loadHashsmithConfig()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.Wordlist), nil
}

// setSavedWordlistDefault validates path and, only if it is genuinely usable,
// saves it. Validation happens BEFORE the write on purpose: the whole value of
// a persisted setting is that it is applied silently on every later run, so a
// setting that was never going to work must be refused at the moment the
// operator can still see the error, not six runs later as a warning they have
// learned to scroll past.
//
// The path is expanded ("~") and made absolute before saving, because the
// setting outlives the shell that created it: a relative path saved from one
// directory means something different from the next one.
func setSavedWordlistDefault(path string) (string, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", fmt.Errorf("--set-default needs a path")
	}
	if expanded := expandWordlistPath(p); expanded != "" {
		p = expanded
	} else if strings.HasPrefix(p, "~") {
		return "", fmt.Errorf("cannot expand %q: the home directory is unavailable", path)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", path, err)
	}
	if problem := wordlistFileProblem(abs); problem != "" {
		return "", fmt.Errorf("refusing to save %s as the default wordlist: %s", abs, problem)
	}
	cfg, err := loadHashsmithConfig()
	if err != nil {
		// The existing file is unreadable or corrupt. Saving over it is the
		// right move — it is what --set-default is for — but say what happened
		// rather than silently discarding settings that may have been in it.
		fmt.Fprintf(os.Stderr, "Note: replacing the previous settings file (%v)\n", err)
		cfg = hashsmithConfig{}
	}
	cfg.Wordlist = abs
	if err := saveHashsmithConfig(cfg); err != nil {
		return "", err
	}
	return abs, nil
}

// clearSavedWordlistDefault removes the pinned default, leaving any other
// settings in the file intact. Clearing an already-clear default is not an
// error: `--clear-default` is what an operator reaches for when a warning
// tells them to, and it must work whether or not the setting is still there.
func clearSavedWordlistDefault() (string, bool, error) {
	cfg, err := loadHashsmithConfig()
	if err != nil {
		// A corrupt file cannot be edited in place without inventing content,
		// so it is replaced with a valid, empty one — which is exactly what
		// "clear the default" should leave behind.
		cfg = hashsmithConfig{}
	}
	had := strings.TrimSpace(cfg.Wordlist)
	cfg.Wordlist = ""
	if err := saveHashsmithConfig(cfg); err != nil {
		return had, had != "", err
	}
	return had, had != "", nil
}

// wordlistFileProblem returns a human-readable reason why path is not usable
// as a wordlist, or "" when it is fine. It is the single definition of
// "usable" shared by --set-default's up-front validation and the stale-default
// check at resolution time, so the two can never disagree about what counts.
func wordlistFileProblem(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "no such file"
		}
		return "cannot stat it: " + err.Error()
	}
	if info.IsDir() {
		return "it is a directory, not a wordlist"
	}
	if !info.Mode().IsRegular() {
		return "it is not a regular file"
	}
	if info.Size() == 0 {
		return "it is empty (0 bytes) — an interrupted download or a truncated install"
	}
	f, err := os.Open(path)
	if err != nil {
		return "it cannot be read: " + err.Error()
	}
	f.Close()
	return ""
}
