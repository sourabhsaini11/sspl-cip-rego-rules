package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/conformance"
)

// scratchRoot builds a one-ruleset repository root around the demo policy and the given tests.
func scratchRoot(t *testing.T, tests string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "rulesets", "demo", "v1")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	write := func(path, content string) { require.NoError(t, os.WriteFile(path, []byte(content), 0o600)) }
	write(filepath.Join(root, "rulesets", "manifest.template.json"),
		`{"rulesets":[{"profile":"BRIDGE-DEMO","version":"v1","package":"cip.pde.demo.v1","path":"demo/v1"}]}`)
	write(filepath.Join(dir, "policy.rego"), policy)
	write(filepath.Join(dir, "policy_test.rego"), tests)
	return root
}

func writeAccepted(t *testing.T, root string, accepted []map[string]string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"accepted": accepted})
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "conformance"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, conformance.AcceptedFile), raw, 0o600))
}
