package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// goldenDetectInputs is the frozen corpus that pins detectHashTypes' behaviour.
// It is every self-test vector's ciphertext plus hand-written inputs covering
// cascade branches no vector reaches. Entries are never removed; new ones are
// appended, which appends to the golden file rather than rewriting it.
func goldenDetectInputs() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, v := range universalHashRegistry.vectors {
		add(v.target)
	}
	for _, s := range goldenExtraInputs {
		add(s)
	}
	sort.Strings(out)
	return out
}

// goldenExtraInputs covers shapes the vector corpus does not reach: the
// trailing length-switch fallback, shadow-line peeling, encoded inputs, and
// the ambiguity groups whose ORDER is the thing most at risk in a refactor.
var goldenExtraInputs = []string{
	"5f4dcc3b5aa765d61d8327deb882cf99",
	"5F4DCC3B5AA765D61D8327DEB882CF99",
	"aad3b435b51404eeaad3b435b51404ee",
	"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	"0123456789abcdef",
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef",
	"root:$6$salt$hash",
	"user:5f4dcc3b5aa765d61d8327deb882cf99",
	"not a hash at all",
	"",
	"deadbeef:cafebabe",
	"deadbeefdeadbeef:cafebabecafebabe",
}

func TestDetectHashTypesGolden(t *testing.T) {
	var sb strings.Builder
	for _, in := range goldenDetectInputs() {
		sb.WriteString(in)
		sb.WriteString("\t")
		sb.WriteString(strings.Join(detectHashTypes(in), ","))
		sb.WriteString("\n")
	}
	got := sb.String()

	const path = "testdata/detect_golden.txt"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden file written")
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with UPDATE_GOLDEN=1)", err)
	}
	if got != string(want) {
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("detection changed at line %d\n  golden: %s\n  now:    %s",
					i+1, wantLines[i], gotLines[i])
			}
		}
		t.Fatalf("golden has %d lines, output has %d", len(wantLines), len(gotLines))
	}
}
