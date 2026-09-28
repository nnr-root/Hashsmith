package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A linker flag naming a symbol that does not exist is not an error. `go build
// -ldflags "-X main.version=1.3.0"` against a package with no main.version
// succeeds, sets nothing, and the binary reports "dev" — which is exactly what
// happened when the implementation moved out of package main and nothing
// noticed until a release would have shipped unidentifiable binaries.
//
// This test reads the actual build configurations and checks that every
// symbol they stamp is one this package declares. It is the only thing
// standing between a future move and the same silent failure.

var ldflagSymbol = regexp.MustCompile(`-X\s+([A-Za-z0-9_./-]+)\.([A-Za-z_][A-Za-z0-9_]*)=`)

func TestLdflagsNameSymbolsThisPackageDeclares(t *testing.T) {
	root := repoRootForLdflags(t)
	sources := []string{
		filepath.Join(root, "Dockerfile"),
		filepath.Join(root, ".github", "workflows", "release.yml"),
		filepath.Join(root, "hashsmith", "cli.py"),
		filepath.Join(root, "scripts", "install.js"),
	}

	declared := declaredVarsInThisPackage(t)
	checked := 0

	for _, path := range sources {
		body, err := os.ReadFile(path)
		if err != nil {
			// A build configuration that is not in this checkout is not a
			// failure; one that is, and names a symbol we do not have, is.
			t.Logf("skipping %s: %v", filepath.Base(path), err)
			continue
		}
		for _, m := range ldflagSymbol.FindAllStringSubmatch(string(body), -1) {
			pkg, symbol := m[1], m[2]
			checked++
			if pkg != "main" {
				t.Errorf("%s stamps %s.%s; the command is package main and -X must name it",
					filepath.Base(path), pkg, symbol)
				continue
			}
			if !declared[symbol] {
				t.Errorf("%s stamps main.%s, which cmd/hashsmith does not declare — "+
					"the flag is a silent no-op and the binary will report \"dev\"",
					filepath.Base(path), symbol)
			}
		}
	}

	if checked == 0 {
		t.Fatal("found no -X flags in any build configuration; this test is no longer checking anything")
	}
	// The three the release path stamps. If one is dropped the binary loses
	// part of its identity, which is worth noticing.
	for _, want := range []string{"version", "commit", "buildDate"} {
		if !declared[want] {
			t.Errorf("cmd/hashsmith does not declare %q", want)
		}
	}
}

// declaredVarsInThisPackage returns the package-level variable names in
// main.go, read from the source rather than from a list kept in step by hand.
func declaredVarsInThisPackage(t *testing.T) map[string]bool {
	t.Helper()
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*""`)
	out := map[string]bool{}
	inVarBlock := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "var (":
			inVarBlock = true
			continue
		case inVarBlock && trimmed == ")":
			inVarBlock = false
			continue
		}
		if !inVarBlock {
			continue
		}
		if m := decl.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// repoRootForLdflags walks up until it finds the directory holding the
// Dockerfile, so the test does not care how deep the package sits.
func repoRootForLdflags(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("no Dockerfile above this package; not a full checkout")
	return ""
}
