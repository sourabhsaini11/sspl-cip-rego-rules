package rulesgen

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadStrict feeds arbitrary bytes to the strict reader the manifest, templates and published profiles go through: no panic, one
// answer for one input (SSPL-NFR 15.2).
func FuzzReadStrict(f *testing.F) {
	for _, seed := range []string{"", "{}", "[", `{"rulesets":[]}`, "{\"rulesets\":[]}\n{}", `{"unknown":1}`, "\x00\xff"} {
		f.Add([]byte(seed))
	}
	if raw, err := os.ReadFile("../../rulesets/manifest.template.json"); err == nil {
		f.Add(raw)
	}
	path := filepath.Join(f.TempDir(), "in.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var a, b manifestFile
		ea, eb := readStrict(path, &a), readStrict(path, &b)
		if (ea == nil) != (eb == nil) {
			t.Fatalf("the same bytes gave different answers: %v and %v", ea, eb)
		}
	})
}
