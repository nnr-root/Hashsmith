package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleFile writes lines to a temp .rule file and returns its path.
func writeRuleFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.rule")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	return path
}

// TestBuildRuleEngineRejectsUnparsableRules is the safety property behind the
// whole rule-compatibility effort: if Hashsmith cannot parse part of a rule
// file it must SAY SO and stop, not quietly search a smaller keyspace and then
// report "not found". A silently-shrunk keyspace is indistinguishable from a
// password that was never there.
func TestBuildRuleEngineRejectsUnparsableRules(t *testing.T) {
	path := writeRuleFile(t, "$1", "\x01bogus", "$2")

	_, err := buildRuleEngine([]string{path}, false, false)
	if err == nil {
		t.Fatal("expected an error for a rule file with unparsable lines, got nil")
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("error should report how many rules could not be parsed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--rules-lenient") {
		t.Errorf("error should name the opt-out flag, got: %v", err)
	}
}

// TestBuildRuleEngineLenientSkipsUnparsableRules keeps the old behaviour
// available for anyone who genuinely wants a partial run.
func TestBuildRuleEngineLenientSkipsUnparsableRules(t *testing.T) {
	path := writeRuleFile(t, "$1", "\x01bogus", "$2")

	e, err := buildRuleEngine([]string{path}, false, true)
	if err != nil {
		t.Fatalf("lenient mode should not error: %v", err)
	}
	if got := e.count(); got != 2 {
		t.Errorf("lenient mode: got %d valid rules, want 2", got)
	}
}

// TestBuildRuleEngineAcceptsFullyValidFile confirms strict mode is not merely
// refusing everything.
func TestBuildRuleEngineAcceptsFullyValidFile(t *testing.T) {
	path := writeRuleFile(t, ":", "$1", "u", "O12", "30 ", "E")

	e, err := buildRuleEngine([]string{path}, false, false)
	if err != nil {
		t.Fatalf("a fully valid rule file must load in strict mode: %v", err)
	}
	if got := e.count(); got != 6 {
		t.Errorf("got %d rules, want 6", got)
	}
}

// TestRulesHashcatAlsoRejectsAreSkippedNotFatal covers a case that would
// otherwise make strict mode a regression rather than a safety net.
//
// hashcat's own stock rule files contain lines hashcat itself refuses to
// compile — InsidePro-HashManager.rule carries a bare "z"/"Z" (no position
// operand) and 25 "SXY" rules, and hashcat answers all of them with "No valid
// rules left." Skipping those loses no candidate relative to hashcat, so
// refusing to run the file at all would leave Hashsmith unable to use a
// ruleset hashcat handles fine. They are reported and skipped; anything else
// unparsable is still a hard error.
func TestRulesHashcatAlsoRejectsAreSkippedNotFatal(t *testing.T) {
	path := writeRuleFile(t, "$1", "z", "Z", "Sa@", "So0", "$2")

	e, err := buildRuleEngine([]string{path}, false, false)
	if err != nil {
		t.Fatalf("rules hashcat also rejects must not abort the run: %v", err)
	}
	if got := e.count(); got != 2 {
		t.Errorf("got %d usable rules, want 2", got)
	}
}

// TestRulesGenuinelyUnparsableStillFatal keeps the safety net for a real typo,
// which hashcat would have compiled.
func TestRulesGenuinelyUnparsableStillFatal(t *testing.T) {
	path := writeRuleFile(t, "$1", "\x01nonsense", "$2")

	if _, err := buildRuleEngine([]string{path}, false, false); err == nil {
		t.Fatal("a rule neither tool can parse must still abort the run")
	}
}

// TestMixedRuleFileReportsOnlyTheGenuineFailures makes sure the parity-skipped
// lines are not counted toward the fatal total.
func TestMixedRuleFileReportsOnlyTheGenuineFailures(t *testing.T) {
	path := writeRuleFile(t, "$1", "z", "Sa@", "\x01nonsense")

	_, err := buildRuleEngine([]string{path}, false, false)
	if err == nil {
		t.Fatal("expected an error for the genuinely unparsable line")
	}
	if !strings.Contains(err.Error(), "1 rule") {
		t.Errorf("should report 1 genuine failure, not the parity skips: %v", err)
	}
}
