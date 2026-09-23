package smith

import (
	"os/exec"
	"strings"
	"testing"
)

// The completion scripts are generated from the live registries, so a format
// added tomorrow completes without anyone remembering to update them. These
// tests pin that, and pin that the scripts are syntactically valid — a broken
// completion script is worse than none, because the shell reports it on every
// new session.
func TestCompletionScriptsAreGeneratedFromTheRegistries(t *testing.T) {
	types := completionHashTypes()
	if len(types) < 400 {
		t.Errorf("only %d hash types offered; the registry holds far more", len(types))
	}
	codecs := completionCodecTypes()
	if len(codecs) < 40 {
		t.Errorf("only %d codec types offered", len(codecs))
	}
	// A format added in this session must appear without any edit here.
	for _, want := range []string{"descrypt", "skype", "keepass-keyfile", "sha256-utf16lepass-hexsalt"} {
		if !contains(types, want) {
			t.Errorf("hash type %q is missing from completion", want)
		}
	}
	cmds := completionCommandNames()
	for _, want := range []string{"crack", "identify", "completion", "zip2smith"} {
		if !contains(cmds, want) {
			t.Errorf("command %q is missing from completion", want)
		}
	}
	for name, script := range map[string]string{
		"bash": bashCompletion(), "zsh": zshCompletion(), "fish": fishCompletion(),
	} {
		if !strings.Contains(script, "descrypt") {
			t.Errorf("%s script does not carry the type list", name)
		}
		if len(script) < 1000 {
			t.Errorf("%s script is implausibly short (%d bytes)", name, len(script))
		}
	}
}

// A generated script that the shell cannot parse would break every new shell
// session for anyone who installed it, so the syntax is checked with the real
// shell where one is available.
func TestCompletionScriptsParse(t *testing.T) {
	for _, c := range []struct{ shell, script string }{
		{"bash", bashCompletion()},
		{"zsh", zshCompletion()},
	} {
		c := c
		t.Run(c.shell, func(t *testing.T) {
			bin, err := exec.LookPath(c.shell)
			if err != nil {
				t.Skipf("%s is not installed here", c.shell)
			}
			cmd := exec.Command(bin, "-n", "/dev/stdin")
			cmd.Stdin = strings.NewReader(c.script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s rejected the generated script: %v\n%s", c.shell, err, out)
			}
		})
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
