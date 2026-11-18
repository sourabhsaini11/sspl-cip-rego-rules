package rulescheck_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulescheck"
)

// The control-plane rules (docs/rules-contract.md in the PDS, section 11) have their own gate: their own manifest, their
// own reason registry, a closed set of output keys, and no package in common with the runtime bundle.

const (
	controlManifest = "control/manifest.template.json"
	controlReasons  = "contract/control-reasons.json"
	validatePolicy  = "control/validate_configuration/v1/policy.rego"
	validateTests   = "control/validate_configuration/v1/policy_test.rego"
	validateExample = "control/validate_configuration/v1/examples.json"
)

func controlProblems(t *testing.T, root string) []string {
	t.Helper()
	ps, err := rulescheck.CheckControl(context.Background(), root)
	require.NoError(t, err)
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// controlScratch copies the runtime and control rules and both registries so a test can break them.
func controlScratch(t *testing.T) string {
	t.Helper()
	root := scratch(t)
	require.NoError(t, os.CopyFS(filepath.Join(root, "control"), os.DirFS(filepath.Join(repoRoot, "control"))))
	return root
}

func TestTheCheckedInControlRulesPassEveryCheck(t *testing.T) {
	require.Empty(t, controlProblems(t, repoRoot))
}

func TestEachKindOfControlDefectIsCaught(t *testing.T) {
	cases := map[string]struct {
		break_ func(t *testing.T, root string)
		want   []string
	}{
		"a ruleset without tests is not shippable": {
			func(t *testing.T, root string) { remove(t, root, validateTests) },
			[]string{"validate_configuration/v1", "policy_test.rego"},
		},
		"a limit written into a rule": {
			func(t *testing.T, root string) {
				edit(t, root, validatePolicy, func(s string) string { return s + "\nforged_limit := 20000\n" })
			},
			[]string{"20000", "policy data"},
		},
		"a reason nobody registered": {
			func(t *testing.T, root string) {
				edit(t, root, validatePolicy, func(s string) string { return s + "\nunregistered := \"SOMETHING_NEW\"\n" })
			},
			[]string{"SOMETHING_NEW", "not registered"},
		},
		"a registered reason no rule uses": {
			func(t *testing.T, root string) {
				editControlReasons(t, root, func(m map[string]any) {
					m["reasons"] = append(m["reasons"].([]any), map[string]any{"ruleset": "validate_configuration", "reason": "NOBODY_USES_THIS", "rule_ref": "RULE-ZZZ-999"})
				})
			},
			[]string{"NOBODY_USES_THIS", "no rule uses"},
		},
		"a package in the wrong namespace": {
			func(t *testing.T, root string) {
				edit(t, root, controlManifest, replaceAll("cip.pde.control.validate_configuration.v1", "cip.pde.validate_configuration.v1"))
			},
			[]string{"cip.pde.control."},
		},
		"a control package listed in the runtime bundle": {
			func(t *testing.T, root string) {
				edit(t, root, manifestRel, func(s string) string {
					return replaceFirst(s, `"package": "cip.pde.bridge_upi.v5"`, `"package": "cip.pde.control.validate_configuration.v1"`)
				})
			},
			[]string{"runtime bundle", "control"},
		},
		"an output that could be read as an approval": {
			func(t *testing.T, root string) {
				edit(t, root, validatePolicy, replaceAll(`"provenance": provenance`, `"provenance": provenance, "approved": true`))
			},
			[]string{"approved", "output key"},
		},
		"a ruleset that ships no examples": {
			func(t *testing.T, root string) { remove(t, root, validateExample) },
			[]string{"examples.json"},
		},
		"a missing control registry": {
			func(t *testing.T, root string) { remove(t, root, controlReasons) },
			[]string{"control-reasons.json"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := controlScratch(t)
			c.break_(t, root)
			requireProblem(t, controlProblems(t, root), c.want...)
		})
	}
}

func replaceFirst(s, old, repl string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + repl + s[i+len(old):]
		}
	}
	return s
}
