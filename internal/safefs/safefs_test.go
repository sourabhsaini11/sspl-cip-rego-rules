package safefs_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAFileUnderTheLimitIsReadWhole(t *testing.T) {
	got, err := safefs.ReadFileMax(write(t, "a.json", "12345"), 5)
	if err != nil || string(got) != "12345" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAFileOverTheLimitIsRefusedNotTruncated(t *testing.T) {
	got, err := safefs.ReadFileMax(write(t, "a.json", "123456"), 5)
	if err == nil || got != nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAMissingFileStillReportsNotExist(t *testing.T) {
	_, err := safefs.ReadFile(filepath.Join(t.TempDir(), "absent.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("callers test errors.Is(err, os.ErrNotExist): %v", err)
	}
}

func TestADirectoryIsRefused(t *testing.T) {
	if _, err := safefs.ReadFile(t.TempDir()); err == nil {
		t.Fatal("a directory was read as a file")
	}
}

func TestASymbolicLinkIsRefusedEvenWhenItPointsAtARealFile(t *testing.T) {
	target := write(t, "real.json", "{}")
	link := filepath.Join(filepath.Dir(target), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks are not available here: " + err.Error())
	}
	if _, err := safefs.ReadFile(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a symlink was followed: %v", err)
	}
}

func TestAPathFromADataFileCannotLeaveItsRoot(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"", "../x", "a/../../x", "/etc/passwd", ".."} {
		if p, err := safefs.Join(root, bad); err == nil {
			t.Errorf("%q was accepted as %s", bad, p)
		}
	}
	for rel, want := range map[string]string{"bridge_upi/v7": filepath.Join(root, "bridge_upi", "v7"), "a/./b": filepath.Join(root, "a", "b")} {
		got, err := safefs.Join(root, rel)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v, want %q", rel, got, err, want)
		}
	}
}

// Whatever a data file says, a joined path stays inside its root.
func FuzzJoinNeverLeavesItsRoot(f *testing.F) {
	for _, seed := range []string{"", "a", "a/b", "../x", "a/../../x", "/abs", "..", ".", "a//b", "a/./b", "\x00", "a\\..\\b"} {
		f.Add(seed)
	}
	root := filepath.Join(string(filepath.Separator), "repo", "rulesets")
	f.Fuzz(func(t *testing.T, rel string) {
		got, err := safefs.Join(root, rel)
		if err != nil {
			return
		}
		inside, relErr := filepath.Rel(root, got)
		if relErr != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			t.Fatalf("%q escaped %s: %s", rel, root, got)
		}
	})
}
