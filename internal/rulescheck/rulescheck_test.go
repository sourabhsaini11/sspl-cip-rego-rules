package rulescheck_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulescheck"
)

const repoRoot = "../.."

func problems(t *testing.T, root string) []string {
	t.Helper()
	ps, err := rulescheck.Check(context.Background(), root)
	require.NoError(t, err)
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// requireProblem passes when one reported problem mentions every part.
func requireProblem(t *testing.T, got []string, parts ...string) {
	t.Helper()
	for _, g := range got {
		all := true
		for _, p := range parts {
			if !strings.Contains(g, p) {
				all = false
				break
			}
		}
		if all {
			return
		}
	}
	t.Fatalf("no problem mentions %q; got:\n  %s", parts, strings.Join(got, "\n  "))
}

// scratch copies the checked-in rulesets and contract so a test can break them.
func scratch(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"rulesets", "contract", "templates", "policy-data"} {
		require.NoError(t, os.CopyFS(filepath.Join(root, d), os.DirFS(filepath.Join(repoRoot, d))))
	}
	return root
}

func edit(t *testing.T, root, rel string, f func(string) string) {
	t.Helper()
	p := filepath.Join(root, rel)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	out := f(string(b))
	require.NotEqual(t, string(b), out, "the edit changed nothing in %s", rel)
	require.NoError(t, os.WriteFile(p, []byte(out), 0o600))
}

func replaceAll(old, repl string) func(string) string {
	return func(s string) string { return strings.ReplaceAll(s, old, repl) }
}

// editReasons rewrites the reason registry through f.
func editReasons(t *testing.T, root string, f func(map[string]any)) {
	t.Helper()
	p := filepath.Join(root, reasonsRel)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	f(m)
	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, out, 0o600))
}

func remove(t *testing.T, root, rel string) {
	t.Helper()
	require.NoError(t, os.Remove(filepath.Join(root, rel)))
}

const (
	upiPolicy   = "rulesets/bridge_upi/v5/policy.rego"
	upiTests    = "rulesets/bridge_upi/v5/policy_test.rego"
	upiSchema   = "rulesets/bridge_upi/v5/fact-schema.json"
	aepsPolicy  = "rulesets/bridge_aeps/v2/policy.rego"
	aepsSchema  = "rulesets/bridge_aeps/v2/fact-schema.json"
	balPolicy   = "rulesets/bridge_balance_inquiry/v1/policy.rego"
	manifestRel = "rulesets/manifest.template.json"
	reasonsRel  = "contract/reasons.json"
)

// The rules that ship pass every check. This is the sync test: if the contract the PDS
// enforces and these rules ever drift apart, it fails here, before a bundle is signed.
func TestTheCheckedInRulesPassEveryCheck(t *testing.T) {
	require.Empty(t, problems(t, repoRoot))
}

// Each case breaks a copy of the repo in one way and demands the check notices. A check
// that cannot fail proves nothing.
func TestEachKindOfDefectIsCaught(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   []string
	}{
		{"a limit written into a rule", func(t *testing.T, r string) {
			edit(t, r, upiPolicy, func(s string) string { return s + "\nper_txn_cap := 99999\n" })
		}, []string{"literal 99999"}},
		{"a reason that is not registered", func(t *testing.T, r string) {
			edit(t, r, upiPolicy, replaceAll(`"WITHIN_LIMITS"`, `"WITHIN_THE_LIMITS"`))
		}, []string{"WITHIN_THE_LIMITS", "not registered"}},
		{"a registered reason no rule produces", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				m["reasons"] = append(m["reasons"].([]any), map[string]any{
					"profile": "BRIDGE-UPI", "reason": "NEVER_USED", "verdict": "REJECT", "reason_code": "CIP-POL-DENY",
				})
			})
		}, []string{"NEVER_USED", "never produced"}},
		{"a rule using a reason the PDS keeps for itself", func(t *testing.T, r string) {
			edit(t, r, aepsPolicy, replaceAll(`"DAILY_CEILING_EXCEEDED"`, `"RULE_UNDEFINED"`))
		}, []string{"RULE_UNDEFINED", "reserved"}},
		{"a reason_code outside the four CIP-POL codes", func(t *testing.T, r string) {
			edit(t, r, upiPolicy, replaceAll(`"CIP-POL-LIMIT"`, `"CIP-POL-FOO"`))
		}, []string{"CIP-POL-FOO"}},
		{"a registry entry whose verdict and code disagree", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				first := m["reasons"].([]any)[0].(map[string]any)
				first["verdict"] = "REJECT"
				first["reason_code"] = ""
			})
		}, []string{"reason_code"}},
		{"a duplicate registry entry", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				rs := m["reasons"].([]any)
				m["reasons"] = append(rs, rs[0])
			})
		}, []string{"duplicate"}},
		{"a missing registry", func(t *testing.T, r string) { remove(t, r, reasonsRel) }, []string{"reasons.json"}},
		{"a ruleset directory the manifest does not list", func(t *testing.T, r string) {
			dir := filepath.Join(r, "rulesets", "bridge_extra", "v1")
			require.NoError(t, os.MkdirAll(dir, 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package cip.pde.bridge_extra.v1\n"), 0o600))
		}, []string{"bridge_extra/v1", "not in the manifest"}},
		{"a manifest entry whose policy is missing", func(t *testing.T, r string) {
			remove(t, r, "rulesets/bridge_aeps/v2/policy.rego")
		}, []string{"bridge_aeps/v2", "policy.rego"}},
		{"an input contract the PDS does not build", func(t *testing.T, r string) {
			edit(t, r, manifestRel, replaceAll(`"input_contract": "v1"`, `"input_contract": "v2"`))
		}, []string{"input_contract"}},
		{"a package that does not match the manifest", func(t *testing.T, r string) {
			edit(t, r, aepsPolicy, replaceAll("package cip.pde.bridge_aeps.v2", "package cip.pde.bridge_aeps.v3"))
		}, []string{"package"}},
		{"a ruleset with no fact schema", func(t *testing.T, r string) { remove(t, r, aepsSchema) }, []string{"fact-schema.json"}},
		{"a fact schema with an unknown type", func(t *testing.T, r string) {
			edit(t, r, upiSchema, replaceAll(`"type": "int"`, `"type": "float"`))
		}, []string{"unknown type"}},
		{"a ruleset with no tests", func(t *testing.T, r string) { remove(t, r, upiTests) }, []string{"policy_test.rego"}},
		{"a failing Rego test", func(t *testing.T, r string) {
			edit(t, r, upiPolicy, func(s string) string {
				return strings.Replace(s, "input.facts.amount_inr <= input.values.per_txn_limit_inr",
					"input.facts.amount_inr <= input.values.daily_limit_inr", 1)
			})
		}, []string{"Rego test"}},
		{"a policy that does not parse", func(t *testing.T, r string) {
			edit(t, r, upiPolicy, func(s string) string { return s + "\n{{{\n" })
		}, []string{"parse"}},
		{"a policy with no decision", func(t *testing.T, r string) {
			edit(t, r, balPolicy, replaceAll("decision :=", "verdict :="))
		}, []string{"decision"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := scratch(t)
			c.mutate(t, root)
			requireProblem(t, problems(t, root), c.want...)
		})
	}
}

const (
	amountRule  = "templates/amount_per_txn/rule.rego"
	amountTests = "templates/amount_per_txn/rule_test.rego"
	amountMeta  = "templates/amount_per_txn/template.json"
	windowRule  = "templates/time_window/rule.rego"
)

// The P1 templates (docs/rego-rule-sources.md) get the same scrutiny as the rulesets: no
// data, every reason registered, tests that pass. A template is code that runs for every
// profile bound to it, so a defect here is wider than one ruleset.
func TestEachKindOfTemplateDefectIsCaught(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   []string
	}{
		{"a limit written into a template", func(t *testing.T, r string) {
			edit(t, r, amountRule, func(s string) string { return s + "\ncap := 99999\n" })
		}, []string{"literal 99999", "AMOUNT_PER_TXN"}},
		{"a template reason that is not registered", func(t *testing.T, r string) {
			edit(t, r, amountRule, replaceAll(`"AMOUNT_OVER_LIMIT"`, `"AMOUNT_TOO_BIG"`))
		}, []string{"AMOUNT_TOO_BIG", "not registered"}},
		{"a registered template reason no template produces", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				m["template_reasons"] = append(m["template_reasons"].([]any), map[string]any{
					"rule_type": "AMOUNT_PER_TXN", "reason": "NEVER_USED", "verdict": "REJECT", "reason_code": "CIP-POL-LIMIT",
				})
			})
		}, []string{"NEVER_USED", "never produced"}},
		{"a template reason registered for a rule type with no template", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				m["template_reasons"] = append(m["template_reasons"].([]any), map[string]any{
					"rule_type": "QUOTA", "reason": "QUOTA_HIT", "verdict": "REJECT", "reason_code": "CIP-POL-LIMIT",
				})
			})
		}, []string{"QUOTA", "no template"}},
		{"a template returning a reason the PDS keeps for itself", func(t *testing.T, r string) {
			edit(t, r, amountRule, replaceAll(`"AMOUNT_OVER_LIMIT"`, `"RULE_UNDEFINED"`))
		}, []string{"RULE_UNDEFINED", "reserved"}},
		{"a template reason_code outside the four CIP-POL codes", func(t *testing.T, r string) {
			edit(t, r, amountRule, replaceAll(`"CIP-POL-LIMIT"`, `"CIP-POL-FOO"`))
		}, []string{"CIP-POL-FOO"}},
		{"a template in the wrong package", func(t *testing.T, r string) {
			edit(t, r, amountRule, replaceAll("package cip.pde.template.amount_per_txn", "package cip.pde.template.other"))
		}, []string{"package", "AMOUNT_PER_TXN"}},
		{"a template with no decision", func(t *testing.T, r string) {
			edit(t, r, windowRule, replaceAll("decision :=", "verdict :="))
		}, []string{"decision", "TIME_WINDOW"}},
		{"a template that does not parse", func(t *testing.T, r string) {
			edit(t, r, amountRule, func(s string) string { return s + "\n{{{\n" })
		}, []string{"parse", "AMOUNT_PER_TXN"}},
		{"a template with no tests", func(t *testing.T, r string) { remove(t, r, amountTests) }, []string{"rule_test.rego"}},
		{"a failing template test", func(t *testing.T, r string) {
			edit(t, r, amountRule, replaceAll("input.facts.amount_inr <= limit", "input.facts.amount_inr < limit"))
		}, []string{"Rego test"}},
		{"a template with no rule file", func(t *testing.T, r string) { remove(t, r, amountRule) }, []string{"rule.rego"}},
		{"a template with no metadata", func(t *testing.T, r string) { remove(t, r, amountMeta) }, []string{"template.json"}},
		{"metadata for another rule type", func(t *testing.T, r string) {
			edit(t, r, amountMeta, replaceAll(`"AMOUNT_PER_TXN"`, `"DATE_RANGE"`))
		}, []string{"template.json", "rule_type"}},
		{"metadata with an unknown fact type", func(t *testing.T, r string) {
			edit(t, r, amountMeta, replaceAll(`"int"`, `"float"`))
		}, []string{"template.json", "unknown type"}},
		{"a template registry that is missing", func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) { delete(m, "template_reasons") })
		}, []string{"AMOUNT_WITHIN_LIMIT", "not registered"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := scratch(t)
			c.mutate(t, root)
			requireProblem(t, problems(t, root), c.want...)
		})
	}
}

// The registry and the gate follow the seven results of the PDE architecture document
// (section 8): a reason may carry any of them, and a v2 ruleset names them as strings.
func TestTheSevenResultsAreAcceptedAndMisuseIsCaught(t *testing.T) {
	add := func(verdict, code string) func(t *testing.T, r string) {
		return func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				m["reasons"] = append(m["reasons"].([]any), map[string]any{
					"profile": "BRIDGE-UPI", "reason": "NEW_REASON", "verdict": verdict, "reason_code": code,
				})
			})
		}
	}
	// Each of these registers a reason no rule produces, so the only other problem is "never produced".
	onlyStale := func(t *testing.T, got []string) {
		t.Helper()
		for _, g := range got {
			if !strings.Contains(g, "never produced") {
				t.Fatalf("unexpected problem: %s", g)
			}
		}
	}
	for _, v := range []string{"STEP_UP", "NEED_EVIDENCE", "REFER", "DEFER_UNAVAILABLE", "INDETERMINATE", "DENY"} {
		t.Run(v+" with a class is accepted", func(t *testing.T) {
			root := scratch(t)
			add(v, "CIP-POL-TRUST")(t, root)
			onlyStale(t, problems(t, root))
		})
		t.Run(v+" without a class is caught", func(t *testing.T) {
			root := scratch(t)
			add(v, "")(t, root)
			requireProblem(t, problems(t, root), "NEW_REASON", "reason_code")
		})
	}
	t.Run("PERMIT with a class is caught", func(t *testing.T) {
		root := scratch(t)
		add("PERMIT", "CIP-POL-LIMIT")(t, root)
		requireProblem(t, problems(t, root), "NEW_REASON", "reason_code")
	})
	t.Run("PERMIT without a class is accepted", func(t *testing.T) {
		root := scratch(t)
		add("PERMIT", "")(t, root)
		onlyStale(t, problems(t, root))
	})
	t.Run("an unknown verdict is caught", func(t *testing.T) {
		root := scratch(t)
		add("MAYBE", "")(t, root)
		requireProblem(t, problems(t, root), "NEW_REASON", "verdict")
	})
}

func TestAV2RulesetNamingAResultIsNotMistakenForAReason(t *testing.T) {
	root := scratch(t)
	edit(t, root, aepsPolicy, func(s string) string {
		return s + "\nstep_up_probe := {\"result\": \"STEP_UP\", \"reason\": \"DAILY_CEILING_EXCEEDED\"} if false\n"
	})

	require.Empty(t, problems(t, root), "STEP_UP is a result, not an unregistered reason")
}

func TestTheReasonsTheEvaluatorOwnsAreReservedForThePDS(t *testing.T) {
	for _, reserved := range []string{"RULE_OUTPUT_INVALID", "RULE_CONFLICT", "PROVIDER_NOT_PERMITTED", "PURPOSE_NOT_PERMITTED", "RELEASE_EXPIRED", "RELEASE_NOT_YET_VALID", "RELEASE_MISSING", "SNAPSHOT_BELOW_MINIMUM", "OPA_UNAVAILABLE", "RULESET_NOT_LOADED", "FACT_MISSING", "POLICY_BINDING_MISSING", "REGION_MISMATCH", "RELEASE_OUT_OF_CANARY_SCOPE"} {
		t.Run(reserved, func(t *testing.T) {
			root := scratch(t)
			edit(t, root, aepsPolicy, replaceAll(`"DAILY_CEILING_EXCEEDED"`, `"`+reserved+`"`))
			requireProblem(t, problems(t, root), reserved, "reserved")
		})
	}
}

// ---- literals that are not reasons: operations and obligations ----

func TestAnUnregisteredOperationOrObligationIsCaught(t *testing.T) {
	root := scratch(t)
	edit(t, root, "rulesets/bridge_mobile_banking/v1/policy.rego", replaceAll(`"REAUTHENTICATE_SESSION"`, `"RENAMED_OBLIGATION"`))

	requireProblem(t, problems(t, root), "RENAMED_OBLIGATION", "not registered")
}

func TestARegisteredLiteralNoRulesetUsesIsCaught(t *testing.T) {
	root := scratch(t)
	editReasons(t, root, func(m map[string]any) {
		m["literals"] = append(m["literals"].([]any), map[string]any{"profile": "BRIDGE-UPI", "literal": "NOBODY_USES_THIS", "kind": "OBLIGATION"})
	})

	requireProblem(t, problems(t, root), "BRIDGE-UPI/NOBODY_USES_THIS", "never used")
}

func TestALiteralMustHaveAKnownKindAndNotBeAReason(t *testing.T) {
	root := scratch(t)
	editReasons(t, root, func(m map[string]any) {
		lits := m["literals"].([]any)
		lits = append(lits,
			map[string]any{"profile": "BRIDGE-UPI", "literal": "BAD_KIND", "kind": "SECRET"},
			map[string]any{"profile": "BRIDGE-UPI", "literal": "WITHIN_LIMITS", "kind": "OBLIGATION"},
			map[string]any{"profile": "BRIDGE-UPI", "literal": "RULE_UNDEFINED", "kind": "OPERATION"})
		m["literals"] = lits
	})

	got := problems(t, root)
	requireProblem(t, got, "BAD_KIND", "kind must be")
	requireProblem(t, got, "WITHIN_LIMITS", "also registered as a reason")
	requireProblem(t, got, "RULE_UNDEFINED", "reserved")
}

func TestAFactEnumValueIsNotAReasonAndNeedsNoRegistration(t *testing.T) {
	// the mobile ruleset compares device_trust to KNOWN, UNKNOWN and REVOKED: none is registered
	root := scratch(t)
	for _, p := range problems(t, root) {
		require.NotContains(t, p, "KNOWN", "an enum value of the fact schema is not a reason")
	}
}

func TestALiteralForAProfileNotInTheManifestIsCaught(t *testing.T) {
	root := scratch(t)
	editReasons(t, root, func(m map[string]any) {
		m["literals"] = append(m["literals"].([]any), map[string]any{"profile": "BRIDGE-GHOST", "literal": "SOME_OP", "kind": "OPERATION"})
	})

	requireProblem(t, problems(t, root), "BRIDGE-GHOST", "not in the manifest")
}

// editControlReasons rewrites the control reason registry through f.
func editControlReasons(t *testing.T, root string, f func(map[string]any)) {
	t.Helper()
	p := filepath.Join(root, "contract", "control-reasons.json")
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	f(m)
	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, out, 0o600))
}

// The manifest declares how consequential each profile is (PDE architecture document, sections 27 and 29:
// the class drives the failure policy and which traces are kept). The PDS reads it from the signed bundle.
func TestTheRiskClassOfEveryRulesetIsRequiredAndConsistent(t *testing.T) {
	t.Run("a ruleset with no class", func(t *testing.T) {
		root := scratch(t)
		edit(t, root, manifestRel, func(s string) string {
			return strings.Replace(s, `"path": "bridge_balance_inquiry/v1",
      "risk_class": "LOW_RISK"`, `"path": "bridge_balance_inquiry/v1"`, 1)
		})
		requireProblem(t, problems(t, root), "BRIDGE-BALANCE-INQUIRY@v1", "risk_class", "required")
	})
	t.Run("a class the PDS does not know", func(t *testing.T) {
		root := scratch(t)
		edit(t, root, manifestRel, replaceAll(`"risk_class": "LOW_RISK"`, `"risk_class": "HIGH"`))
		requireProblem(t, problems(t, root), "risk_class", `"HIGH"`)
	})
	t.Run("versions of one profile that disagree", func(t *testing.T) {
		root := scratch(t)
		edit(t, root, manifestRel, func(s string) string {
			i := strings.LastIndex(s, `"path": "bridge_upi/v7",
      "risk_class": "CONSEQUENTIAL"`)
			require.Positive(t, i, "test setup")
			return s[:i] + strings.Replace(s[i:], `"risk_class": "CONSEQUENTIAL"`, `"risk_class": "STANDARD"`, 1)
		})
		requireProblem(t, problems(t, root), "BRIDGE-UPI", "risk_class", "versions")
	})
}

// The approved text for GET_SAFE_REASON (PDE architecture document, section 9). The PDS refuses a catalogue with an unapproved entry at
// load; the gate refuses it before it is ever signed, and checks every entry against the reason registry.
const safeReasonsRel = "policy-data/safe-reasons.json"

func catalogue(entries string) string {
	return `{"format":"pde-safe-reasons/v1","entries":[` + entries + `]}`
}

const approvedEntry = `{"profile":"BRIDGE-UPI","reason":"UPI_GUARDED_LIMIT_EXCEEDED","text":"This payment is above the limit that applies right now.","appeal_ref":"APPEAL-UPI-01","approval_ref":"APPR-2026-0007"}`

func TestAnApprovedSafeReasonCatalogueIsAccepted(t *testing.T) {
	root := scratch(t)
	edit(t, root, safeReasonsRel, func(string) string {
		return catalogue(approvedEntry + `,{"reason":"POLICY_REF_MISMATCH","text":"This request could not be matched to an approved policy.","appeal_ref":"APPEAL-GEN-01","approval_ref":"APPR-2026-0008"}`)
	})
	require.Empty(t, problems(t, root), "a registered reason, and one the PDS owns, may both have approved text")
}

func TestATemplateReasonMayHaveApprovedText(t *testing.T) {
	root := scratch(t)
	edit(t, root, safeReasonsRel, func(string) string {
		return catalogue(`{"reason":"AMOUNT_OVER_LIMIT","text":"This amount is above the limit set for this bank.","appeal_ref":"APPEAL-GEN-02","approval_ref":"APPR-2026-0009"}`)
	})
	require.Empty(t, problems(t, root), "a P1 template returns this reason for every profile it is bound to")
}

func TestEachKindOfSafeReasonDefectIsCaught(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"an entry nobody approved", catalogue(strings.Replace(approvedEntry, `"approval_ref":"APPR-2026-0007"`, `"approval_ref":""`, 1)), []string{"safe-reasons", "approval_ref"}},
		{"an entry with no appeal path", catalogue(strings.Replace(approvedEntry, `"appeal_ref":"APPEAL-UPI-01"`, `"appeal_ref":""`, 1)), []string{"safe-reasons", "appeal_ref"}},
		{"a reason no ruleset can produce", catalogue(strings.Replace(approvedEntry, `UPI_GUARDED_LIMIT_EXCEEDED`, `NEVER_RETURNED`, 1)), []string{"NEVER_RETURNED", "not a registered reason"}},
		{"a reason registered for another profile", catalogue(strings.Replace(approvedEntry, `BRIDGE-UPI`, `BRIDGE-BALANCE-INQUIRY`, 1)), []string{"BRIDGE-BALANCE-INQUIRY", "not a registered reason"}},
		{"rego in the text", catalogue(strings.Replace(approvedEntry, `This payment is above the limit that applies right now.`, `deny if input.facts.amount_inr > 8000`, 1)), []string{"text", "rule"}},
		{"a text too long to show", catalogue(strings.Replace(approvedEntry, `This payment is above the limit that applies right now.`, strings.Repeat("a", 401), 1)), []string{"text", "400"}},
		{"the same reason twice", catalogue(approvedEntry + "," + approvedEntry), []string{"twice"}},
		{"an unknown field", catalogue(strings.Replace(approvedEntry, `"reason"`, `"severity":"HIGH","reason"`, 1)), []string{"safe-reasons", "severity"}},
		{"a wrong format", strings.Replace(catalogue(approvedEntry), `pde-safe-reasons/v1`, `v2`, 1), []string{"safe-reasons", "format"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := scratch(t)
			edit(t, root, safeReasonsRel, func(string) string { return tc.content })
			requireProblem(t, problems(t, root), tc.want...)
		})
	}
}

func TestAMissingCatalogueIsNotAProblem(t *testing.T) {
	root := scratch(t)
	require.NoError(t, os.Remove(filepath.Join(root, safeReasonsRel)))
	require.Empty(t, problems(t, root), "no catalogue means the text per result, which is a valid state")
}

// L5 provenance (PDE architecture document sections 14 and 29): a fact schema may say a fact needs a source and name the configuration key that bounds its age.
// The gate applies the PDS's own rules to those keys, because the PDS refuses a bundle whose schema does not parse.
func TestAFactSchemaMayDeclareProvenance(t *testing.T) {
	root := scratch(t)
	edit(t, root, "rulesets/bridge_kcc/v1/fact-schema.json", func(s string) string {
		return strings.Replace(s, `"land_document_area_milli_acres": {"type": "int", "required": true}`,
			`"land_document_area_milli_acres": {"type": "int", "required": true, "source_required": true, "max_age_key": "kcc_source_max_age_seconds"}`, 1)
	})
	require.Empty(t, problems(t, root))
}

func TestAMalformedProvenanceDeclarationIsCaught(t *testing.T) {
	cases := map[string]string{
		"a window with no source requirement": `"max_age_key": "kcc_source_max_age_seconds"`,
		"a window that is not a config key":   `"source_required": true, "max_age_key": "3600"`,
		"an unknown provenance key":           `"source_required": true, "freshness": 3600`,
	}
	for name, decl := range cases {
		t.Run(name, func(t *testing.T) {
			root := scratch(t)
			edit(t, root, "rulesets/bridge_kcc/v1/fact-schema.json", func(s string) string {
				return strings.Replace(s, `"land_document_area_milli_acres": {"type": "int", "required": true}`,
					`"land_document_area_milli_acres": {"type": "int", "required": true, `+decl+`}`, 1)
			})
			requireProblem(t, problems(t, root), "bridge_kcc", "fact")
		})
	}
}

func TestTheReasonsOfFactProvenanceAndQuarantineAreReservedForThePDS(t *testing.T) {
	for _, reason := range []string{"FACT_SOURCE_MISSING", "FACT_SOURCE_STALE", "FACT_SOURCE_SCOPE_MISMATCH", "RULESET_QUARANTINED"} {
		t.Run(reason, func(t *testing.T) {
			root := scratch(t)
			edit(t, root, upiPolicy, replaceAll(`"WITHIN_LIMITS"`, `"`+reason+`"`))
			requireProblem(t, problems(t, root), reason, "reserved")
		})
	}
}

// Cross-tenant denials the rules produce are always traced (PDE architecture document section 30). The registry says which of a profile's reasons cross a tenant
// boundary; the signed manifest carries them to the PDS; the gate makes sure the two agree, because the PDS trusts the manifest and a disagreement would silently
// stop a denial being traced.
func TestTheMobileBankingScopeDenialIsDeclaredAsATenancyReasonAndTheTwoAgree(t *testing.T) {
	require.Empty(t, problems(t, repoRoot))
	raw, err := os.ReadFile(filepath.Join(repoRoot, manifestRel))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"tenancy_reasons": ["BANK_SCOPE_MISMATCH"]`, "the declaration is in the manifest the PDS verifies")
}

func TestADisagreementBetweenTheRegistryAndTheManifestAboutTenancyIsCaught(t *testing.T) {
	cases := map[string]struct {
		mutate func(t *testing.T, r string)
		want   []string
	}{
		"the manifest stops declaring a reason the registry flags": {func(t *testing.T, r string) {
			edit(t, r, manifestRel, replaceAll(",\n      \"tenancy_reasons\": [\"BANK_SCOPE_MISMATCH\"]", ""))
		}, []string{"BRIDGE-MOBILE-BANKING", "BANK_SCOPE_MISMATCH", "tenancy"}},
		"the manifest declares a reason the registry does not flag": {func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				for _, e := range m["reasons"].([]any) {
					if e.(map[string]any)["reason"] == "BANK_SCOPE_MISMATCH" {
						delete(e.(map[string]any), "tenancy")
					}
				}
			})
		}, []string{"BRIDGE-MOBILE-BANKING", "BANK_SCOPE_MISMATCH", "tenancy"}},
		"the manifest declares a reason that is not registered for the profile": {func(t *testing.T, r string) {
			edit(t, r, manifestRel, replaceAll(`"tenancy_reasons": ["BANK_SCOPE_MISMATCH"]`, `"tenancy_reasons": ["BANK_SCOPE_MISMATCH", "NEVER_REGISTERED"]`))
		}, []string{"NEVER_REGISTERED", "tenancy"}},
		"a tenancy reason that is not a denial": {func(t *testing.T, r string) {
			editReasons(t, r, func(m map[string]any) {
				for _, e := range m["reasons"].([]any) {
					if e.(map[string]any)["reason"] == "DEVICE_KNOWN" {
						e.(map[string]any)["tenancy"] = true
					}
				}
			})
		}, []string{"DEVICE_KNOWN", "tenancy", "DENY"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := scratch(t)
			tc.mutate(t, root)
			requireProblem(t, problems(t, root), tc.want...)
		})
	}
}
