package rulesgen_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulesgen"
)

// PDE architecture document section 13: "Configuration-only changes need an approved Configuration Instance, OPA
// validation proof, bank/Operator approval as applicable and a new signed effective-state snapshot. Rule-code changes
// additionally need signed policy bundle promotion. A bundle upload must never silently activate an unapproved bank
// configuration." A published profile (the per-bank rules the Landing Zone binds) is configuration, so with a policy-data
// directory the bindings leave the bundle: the same rules and templates always give the same bundle bytes.

// catalogueTwo has two bindable rules of the one template miniRoot ships, so two profiles can differ.
const catalogueTwo = `{"rules":[
 {"field_path":"R-UPI-TXN-MAX","rule_type":"AMOUNT_PER_TXN","applies_to":["UPI_PAY"]},
 {"field_path":"R-UPI-DAILY-MAX","rule_type":"AMOUNT_PER_TXN","applies_to":["UPI_PAY"]}
]}`

func generateWithPolicyData(t *testing.T, root, profile string) (bundleDir, policyDir string, rep rulesgen.Report) {
	t.Helper()
	d := t.TempDir()
	cat := write(t, d, "catalogue.json", catalogueTwo)
	prof := write(t, d, "profile.json", profile)
	bundleDir = filepath.Join(t.TempDir(), "bundle")
	policyDir = filepath.Join(t.TempDir(), "policy-data")
	rep, err := rulesgen.Generate(rulesgen.Options{Root: root, Catalogue: cat, Profiles: []string{prof}, Out: bundleDir, PolicyDataOut: policyDir})
	require.NoError(t, err)
	return bundleDir, policyDir, rep
}

// dirDigest is a digest of every file in dir: its relative path and content, in path order.
func dirDigest(t *testing.T, dir string) string {
	t.Helper()
	var rels []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			rels = append(rels, rel)
		}
		return err
	}))
	sort.Strings(rels)
	h := sha256.New()
	for _, rel := range rels {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		require.NoError(t, err)
		h.Write([]byte(rel + "\x00"))
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestAConfigurationOnlyPublishDoesNotChangeTheBundleDigest(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	bundleA, dataA, _ := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX"))
	bundleB, dataB, _ := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX", "R-UPI-DAILY-MAX"))
	bundleNone, _, _ := generateWithPolicyData(t, root, upiProfile())

	require.Equal(t, dirDigest(t, bundleA), dirDigest(t, bundleB), "a different bank configuration must not change the bundle")
	require.Equal(t, dirDigest(t, bundleA), dirDigest(t, bundleNone), "nor must having no bank configuration at all")
	require.NotEqual(t, dirDigest(t, dataA), dirDigest(t, dataB), "the configuration is in the policy data")
}

func TestTheBundleCarriesNoBindingsWhenPolicyDataIsRequested(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	bundle, _, rep := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX"))

	require.Equal(t, 2, rep.Bound, "the rules are still bound, on both versions")
	m := readJSON(t, filepath.Join(bundle, "manifest.template.json"))
	require.NotContains(t, m, "bindings", "the bundle manifest lists no bindings")
	require.NoDirExists(t, filepath.Join(bundle, "bindings"))
}

func TestThePolicyDataListsEachBindingFileWithItsDigest(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	_, data, _ := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX"))

	m := readJSON(t, filepath.Join(data, "policy-data.manifest.template.json"))
	require.Equal(t, "pde-policy-data/v1", m["format"])
	require.Equal(t, "pde-policy-data", m["bundle_id"])
	bindings := m["bindings"].([]any)
	require.Len(t, bindings, 2)
	first := bindings[0].(map[string]any)
	require.Equal(t, "BRIDGE-UPI", first["profile"])
	require.Equal(t, "v4", first["version"])
	require.Equal(t, "bindings/bridge_upi/v4.json", first["path"])
	raw, err := os.ReadFile(filepath.Join(data, "bindings", "bridge_upi", "v4.json"))
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), first["digest"], "the digest is what the signature will cover")
}

func TestThePolicyDataIsDeterministic(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	_, a, _ := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX"))
	_, b, _ := generateWithPolicyData(t, root, upiProfile("R-UPI-TXN-MAX"))

	require.Equal(t, dirDigest(t, a), dirDigest(t, b))
}

func TestWithoutAPolicyDataDirectoryTheBindingsStayInTheBundle(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	out, _, err := generateAt(t, root, upiProfile("R-UPI-TXN-MAX"))

	require.NoError(t, err)
	m := readJSON(t, filepath.Join(out, "manifest.template.json"))
	require.Contains(t, m, "bindings", "the legacy layout is unchanged until the PDS loads policy data (plan Task 10)")
}

func TestAPolicyDataDirectoryThatIsNotEmptyIsRefusedAndNothingIsWritten(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	d := t.TempDir()
	cat := write(t, d, "catalogue.json", catalogue)
	prof := write(t, d, "profile.json", upiProfile("R-UPI-TXN-MAX"))
	policyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "stale.json"), []byte("{}"), 0o600))
	out := filepath.Join(t.TempDir(), "bundle")

	_, err := rulesgen.Generate(rulesgen.Options{Root: root, Catalogue: cat, Profiles: []string{prof}, Out: out, PolicyDataOut: policyDir})

	require.ErrorContains(t, err, "not empty")
	require.NoDirExists(t, out, "a refused generation leaves the bundle directory as it was")
}

func TestThePolicyDataDirectoryMustDifferFromTheBundleDirectory(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	d := t.TempDir()
	cat := write(t, d, "catalogue.json", catalogue)
	prof := write(t, d, "profile.json", upiProfile("R-UPI-TXN-MAX"))
	out := filepath.Join(t.TempDir(), "same")

	_, err := rulesgen.Generate(rulesgen.Options{Root: root, Catalogue: cat, Profiles: []string{prof}, Out: out, PolicyDataOut: out})

	require.Error(t, err)
}
