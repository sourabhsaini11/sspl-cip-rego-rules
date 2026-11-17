package rulesgen_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulesgen"
)

// A small repository root with two versions of one profile, so a bank pinned to the older one can
// be told from one on the newer (docs/policy-binding.md in the PDS repository, B-9).

const (
	factsWithAmount = `{"fields":{"amount_inr":{"type":"int","required":true}}}`
	factsWithout    = `{"fields":{"note":{"type":"string"}}}`
)

func miniRoot(t *testing.T, v4Facts string) string {
	t.Helper()
	root := t.TempDir()
	put := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
	put("rulesets/manifest.template.json", `{"bundle_id":"pde-rules","revision":"r1","input_contract":"v1","git_commit":"0000000000000000000000000000000000000000","rulesets":[
 {"profile":"BRIDGE-UPI","version":"v4","package":"cip.pde.bridge_upi.v4","path":"bridge_upi/v4"},
 {"profile":"BRIDGE-UPI","version":"v5","package":"cip.pde.bridge_upi.v5","path":"bridge_upi/v5"}]}`)
	for v, facts := range map[string]string{"v4": v4Facts, "v5": factsWithAmount} {
		put("rulesets/bridge_upi/"+v+"/policy.rego", "package cip.pde.bridge_upi."+v+"\n")
		put("rulesets/bridge_upi/"+v+"/fact-schema.json", facts)
	}
	put("templates/amount_per_txn/template.json", `{"rule_type":"AMOUNT_PER_TXN","requires_facts":{"amount_inr":"int"}}`)
	put("templates/amount_per_txn/rule.rego", "package cip.pde.template.amount_per_txn\n")
	return root
}

func generateAt(t *testing.T, root, profile string) (string, rulesgen.Report, error) {
	t.Helper()
	d := t.TempDir()
	cat := write(t, d, "catalogue.json", catalogue)
	prof := write(t, d, "profile.json", profile)
	out := filepath.Join(t.TempDir(), "bundle")
	rep, err := rulesgen.Generate(rulesgen.Options{Root: root, Catalogue: cat, Profiles: []string{prof}, Out: out})
	return out, rep, err
}

func TestEveryVersionOfAProfileGetsItsBindings(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	out, rep, err := generateAt(t, root, upiProfile("R-UPI-TXN-MAX"))

	require.NoError(t, err)
	require.Equal(t, 2, rep.Bound, "one rule on each of the two versions")
	require.FileExists(t, filepath.Join(out, "bindings/bridge_upi/v4.json"), "a bank pinned to v4 still gets its limit")
	require.FileExists(t, filepath.Join(out, "bindings/bridge_upi/v5.json"))
}

func TestAVersionThatCannotHostAConfiguredRuleFailsTheGeneration(t *testing.T) {
	root := miniRoot(t, factsWithout)

	_, _, err := generateAt(t, root, upiProfile("R-UPI-TXN-MAX"))

	require.ErrorContains(t, err, "v4")
	require.ErrorContains(t, err, "amount_inr", "a rule silently missing on an older version would be a permissive gap")
}

func TestAProfileMayNameTheVersionsItBindsTo(t *testing.T) {
	root := miniRoot(t, factsWithout)
	profile := `{"profile":"BRIDGE-UPI","fields":["R-UPI-TXN-MAX"],"versions":["v5"]}`

	out, rep, err := generateAt(t, root, profile)

	require.NoError(t, err)
	require.Equal(t, 1, rep.Bound)
	require.NoFileExists(t, filepath.Join(out, "bindings/bridge_upi/v4.json"))
	require.FileExists(t, filepath.Join(out, "bindings/bridge_upi/v5.json"))
}

func TestANamedVersionThatDoesNotExistIsRefused(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	profile := `{"profile":"BRIDGE-UPI","fields":["R-UPI-TXN-MAX"],"versions":["v9"]}`

	_, _, err := generateAt(t, root, profile)

	require.ErrorContains(t, err, "v9")
}
