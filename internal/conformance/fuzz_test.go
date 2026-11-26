package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadJSON feeds arbitrary bytes to the reader every corpus, manifest and accepted-mutants file goes through. It must never panic,
// must give the same answer twice, and anything it accepts must encode again (SSPL-NFR 15.2: fuzz parsers of untrusted input).
func FuzzReadJSON(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "[", `{"cases":[]}`, `{"accepted":[]}`, "{\"accepted\":[]}\n{}", `{"cases":[{"name":"x"}],"extra":1}`, "\x00\xff",
	} {
		f.Add([]byte(seed))
	}
	if raw, err := os.ReadFile("../../conformance/compat/bridge_upi.json"); err == nil {
		f.Add(raw)
	}
	path := filepath.Join(f.TempDir(), "in.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, strict := range []bool{true, false} {
			var a, b corpusFile
			ea, eb := readJSON(path, &a, strict), readJSON(path, &b, strict)
			if (ea == nil) != (eb == nil) {
				t.Fatalf("strict=%v: the same bytes gave different answers: %v and %v", strict, ea, eb)
			}
			if ea == nil {
				if _, err := json.Marshal(a); err != nil {
					t.Fatalf("an accepted document cannot be encoded: %v", err)
				}
			}
		}
	})
}
