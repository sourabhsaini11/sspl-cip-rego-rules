package rulesgen_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulesgen"
)

const repoRoot = "../.."

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// A catalogue export (the Definition Catalogue's profile_field_rule_catalogue, one row per
// rule, applies_to already split into operations) and the profile a publish carries.
const catalogue = `{"rules":[
 {"field_path":"R-UPI-TXN-MAX","rule_type":"AMOUNT_PER_TXN","applies_to":["UPI_PAY"]},
 {"field_path":"R-UPI-WINDOW","rule_type":"TIME_WINDOW","applies_to":["UPI_PAY"]},
 {"field_path":"R-UPI-STMT-RANGE","rule_type":"DATE_RANGE","applies_to":["UPI_PAY"]},
 {"field_path":"R-UPI-QUOTA","rule_type":"QUOTA","applies_to":["UPI_PAY"]},
 {"field_path":"R-UPI-ALL-WRITES","rule_type":"AMOUNT_PER_TXN","applies_to":["op_class: WRITE"]}
]}`

func upiProfile(fields ...string) string {
	b, _ := json.Marshal(map[string]any{"profile": "BRIDGE-UPI", "fields": fields})
	return string(b)
}

type inputs struct{ catalogue, profile, out string }

func setup(t *testing.T, cat, profile string) inputs {
	t.Helper()
	d := t.TempDir()
	return inputs{
		catalogue: write(t, d, "catalogue.json", cat),
		profile:   write(t, d, "profile.json", profile),
		out:       filepath.Join(t.TempDir(), "bundle"),
	}
}

func generate(in inputs) (rulesgen.Report, error) {
	return rulesgen.Generate(rulesgen.Options{Root: repoRoot, Catalogue: in.catalogue, Profiles: []string{in.profile}, Out: in.out})
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestAPublishedProfileBecomesBindingsOnEveryVersionOfItsRuleset(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX"))

	rep, err := generate(in)

	require.NoError(t, err)
	require.Equal(t, 3, rep.Bound, "one rule on each of v5, v6 and v7")
	b := readJSON(t, filepath.Join(in.out, "bindings/bridge_upi/v5.json"))
	require.Equal(t, map[string]any{"rules": []any{map[string]any{
		"rule_id": "R-UPI-TXN-MAX", "rule_type": "AMOUNT_PER_TXN",
		"operations": []any{"UPI_PAY"}, "value_key": "R-UPI-TXN-MAX",
	}}}, b)

	m := readJSON(t, filepath.Join(in.out, "manifest.template.json"))
	require.Equal(t, []any{
		map[string]any{"profile": "BRIDGE-UPI", "version": "v5", "path": "bindings/bridge_upi/v5.json"},
		map[string]any{"profile": "BRIDGE-UPI", "version": "v6", "path": "bindings/bridge_upi/v6.json"},
		map[string]any{"profile": "BRIDGE-UPI", "version": "v7", "path": "bindings/bridge_upi/v7.json"},
	}, m["bindings"])
	tpls := m["templates"].([]any)
	require.Len(t, tpls, 3, "every template in the repository ships")
	require.Equal(t, map[string]any{"rule_type": "AMOUNT_PER_TXN", "package": "cip.pde.template.amount_per_txn", "path": "templates/amount_per_txn"}, tpls[0])
	for _, p := range []string{"templates/amount_per_txn/rule.rego", "bridge_upi/v5/policy.rego", "bridge_upi/v5/fact-schema.json"} {
		require.FileExists(t, filepath.Join(in.out, p))
	}
	require.NoFileExists(t, filepath.Join(in.out, "templates/amount_per_txn/rule_test.rego"), "tests are for reviewers, not the bundle")
}

func TestABindingNeverCarriesANumber(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX", "R-UPI-WINDOW"))
	_, err := generate(in)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(in.out, "bindings/bridge_upi/v5.json"))
	require.NoError(t, err)
	var f struct {
		Rules []map[string]any `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	for _, r := range f.Rules {
		for k, v := range r {
			if _, isNumber := v.(float64); isNumber {
				t.Fatalf("binding field %q is a number: a limit belongs in the signed state, not in the bundle", k)
			}
		}
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	cat, prof := catalogue, upiProfile("R-UPI-WINDOW", "R-UPI-TXN-MAX")
	a, b := setup(t, cat, prof), setup(t, cat, prof)
	_, err := generate(a)
	require.NoError(t, err)
	_, err = generate(b)
	require.NoError(t, err)
	for _, rel := range []string{"bindings/bridge_upi/v5.json", "manifest.template.json"} {
		x, err := os.ReadFile(filepath.Join(a.out, rel))
		require.NoError(t, err)
		y, err := os.ReadFile(filepath.Join(b.out, rel))
		require.NoError(t, err)
		require.Equal(t, string(x), string(y), rel)
	}
	b1 := readJSON(t, filepath.Join(a.out, "bindings/bridge_upi/v5.json"))["rules"].([]any)
	require.Equal(t, "R-UPI-TXN-MAX", b1[0].(map[string]any)["rule_id"], "ordered by rule type, then rule id")
	require.Equal(t, "R-UPI-WINDOW", b1[1].(map[string]any)["rule_id"])
}

func TestRuleTypesWithoutATemplateAreSkippedAndReported(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX", "R-UPI-QUOTA", "R-UPI-ALL-WRITES"))
	rep, err := generate(in)
	require.NoError(t, err)
	require.Equal(t, 3, rep.Bound)
	require.ElementsMatch(t, []rulesgen.Skip{
		{RuleID: "R-UPI-QUOTA", Why: "no template for rule type QUOTA"},
		{RuleID: "R-UPI-ALL-WRITES", Why: `applies to an operation class, not an operation ("op_class: WRITE")`},
	}, rep.Skipped)
}

func TestAProfileWithNothingBindableChangesNothing(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-QUOTA"))
	rep, err := generate(in)
	require.NoError(t, err)
	require.Zero(t, rep.Bound)
	require.NoFileExists(t, filepath.Join(in.out, "bindings/bridge_upi/v5.json"))
	require.NotContains(t, readJSON(t, filepath.Join(in.out, "manifest.template.json")), "bindings")
}

func TestGenerationRefuses(t *testing.T) {
	cases := []struct {
		name         string
		cat, profile string
		want         string
	}{
		{"a field that is not in the catalogue", catalogue, upiProfile("R-NOPE"), "R-NOPE"},
		{"a profile with no ruleset in the manifest", catalogue, `{"profile":"BRIDGE-NOPE","fields":["R-UPI-TXN-MAX"]}`, "BRIDGE-NOPE"},
		{"a template that reads a fact the ruleset does not declare", catalogue, upiProfile("R-UPI-STMT-RANGE"), "from_date"},
		{"a field listed twice", catalogue, upiProfile("R-UPI-TXN-MAX", "R-UPI-TXN-MAX"), "twice"},
		{"a catalogue row listed twice", `{"rules":[{"field_path":"R-A","rule_type":"AMOUNT_PER_TXN","applies_to":["UPI_PAY"]},{"field_path":"R-A","rule_type":"AMOUNT_PER_TXN","applies_to":["UPI_PAY"]}]}`, upiProfile("R-A"), "R-A"},
		{"an unknown key in the profile", catalogue, `{"profile":"BRIDGE-UPI","fields":[],"limit":5}`, "unknown field"},
		{"a catalogue that is not JSON", `{`, upiProfile("R-UPI-TXN-MAX"), "catalogue"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := setup(t, tc.cat, tc.profile)
			_, err := generate(in)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
			require.NoDirExists(t, in.out, "a refused generation leaves nothing behind")
		})
	}
}

func TestGenerationRefusesToWriteIntoANonEmptyDirectory(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX"))
	require.NoError(t, os.MkdirAll(in.out, 0o750))
	write(t, in.out, "keep.txt", "x")
	_, err := generate(in)
	require.ErrorContains(t, err, "not empty")
}

func TestTheGeneratedManifestKeepsTheRiskClassOfEveryRuleset(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX"))

	_, err := generate(in)

	require.NoError(t, err)
	m := readJSON(t, filepath.Join(in.out, "manifest.template.json"))
	classes := map[string]string{}
	for _, e := range m["rulesets"].([]any) {
		r := e.(map[string]any)
		classes[r["profile"].(string)+"@"+r["version"].(string)], _ = r["risk_class"].(string)
	}
	require.Equal(t, "CONSEQUENTIAL", classes["BRIDGE-UPI@v7"], "the class is signed with the bundle, so it must survive generation")
	require.Equal(t, "LOW_RISK", classes["BRIDGE-BALANCE-INQUIRY@v1"])
	for id, c := range classes {
		require.NotEmpty(t, c, id)
	}
}

func TestTheGeneratedManifestKeepsTheTenancyReasons(t *testing.T) {
	in := setup(t, catalogue, upiProfile("R-UPI-TXN-MAX"))

	_, err := generate(in)

	require.NoError(t, err)
	m := readJSON(t, filepath.Join(in.out, "manifest.template.json"))
	var declared []any
	for _, e := range m["rulesets"].([]any) {
		r := e.(map[string]any)
		if r["profile"] == "BRIDGE-MOBILE-BANKING" {
			declared, _ = r["tenancy_reasons"].([]any)
		}
	}
	require.Equal(t, []any{"BANK_SCOPE_MISMATCH"}, declared, "the declaration is signed with the bundle, so it must survive generation")
}
