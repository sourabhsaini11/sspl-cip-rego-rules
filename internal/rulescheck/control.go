package rulescheck

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// The control-plane rules (PDE architecture document component 2 and Journey 8; docs/rules-contract.md in the PDS,
// section 11) run in the Landing Zone's Control Plane OPA, never in the PDS. They are their own family with their own
// manifest and reason registry, so a control rule can never ship in the runtime bundle or the reverse (section 36 leaves
// the Control/Runtime separation open; decision D-5 keeps them apart). OPA only says whether a proposal is technically
// permissible: no output may be readable as an approval.

const (
	controlManifestRel    = "control/manifest.template.json"
	controlReasonsRel     = "contract/control-reasons.json"
	controlPackagePrefix  = "cip.pde.control."
	controlBundleID       = "pde-control-rules"
	controlInputContract  = "control-v1"
	controlExamplesFile   = "examples.json"
	controlRulesetsDirRel = "control"
)

var ruleRefRe = regexp.MustCompile(`^RULE-[A-Z]{3}-[0-9]{3}$`)

type controlManifest struct {
	BundleID      string         `json:"bundle_id"`
	Revision      string         `json:"revision"`
	InputContract string         `json:"input_contract"`
	GitCommit     string         `json:"git_commit"`
	Rulesets      []controlEntry `json:"rulesets"`
}

type controlEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Package string `json:"package"`
	Path    string `json:"path"`
}

type controlReason struct {
	Ruleset string `json:"ruleset"`
	Reason  string `json:"reason"`
	RuleRef string `json:"rule_ref"`
}

type controlLiteral struct {
	Ruleset string `json:"ruleset"`
	Literal string `json:"literal"`
}

type controlRegistry struct {
	RegistryVersion int                 `json:"registry_version"`
	Description     string              `json:"description"`
	Reasons         []controlReason     `json:"reasons"`
	Literals        []controlLiteral    `json:"literals"`
	Results         []string            `json:"results"`
	OutputKeys      map[string][]string `json:"output_keys"`
}

type controlExample struct {
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

// CheckControl inspects the control-plane rules under root. A returned error means the check itself could not run;
// anything wrong with the rules is a Problem.
func CheckControl(ctx context.Context, root string) ([]Problem, error) {
	c := &checker{root: root}
	reg := c.loadControlRegistry()
	m := c.loadControlManifest()
	c.checkSeparation(m)
	if m != nil && reg != nil {
		c.checkControlManifest(m, reg)
		for _, e := range m.Rulesets {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.checkControlRuleset(ctx, e, reg)
		}
	}
	return c.problems, ctx.Err()
}

func (c *checker) loadControlRegistry() *controlRegistry {
	raw, err := os.ReadFile(filepath.Join(c.root, controlReasonsRel))
	if err != nil {
		c.add(controlReasonsRel, "cannot read control-reasons.json: %v", err)
		return nil
	}
	var r controlRegistry
	if err := decodeStrict(raw, &r); err != nil {
		c.add(controlReasonsRel, "does not decode: %v", err)
		return nil
	}
	seen := map[string]bool{}
	for _, e := range r.Reasons {
		key := e.Ruleset + "|" + e.Reason
		switch {
		case !reasonRe.MatchString(e.Reason):
			c.add(controlReasonsRel, "reason %q must be UPPER_SNAKE_CASE", e.Reason)
		case !ruleRefRe.MatchString(e.RuleRef):
			c.add(controlReasonsRel, "reason %s: rule_ref %q must look like RULE-ABC-001", e.Reason, e.RuleRef)
		case seen[key]:
			c.add(controlReasonsRel, "reason %s is registered twice for %s", e.Reason, e.Ruleset)
		}
		seen[key] = true
	}
	return &r
}

func (c *checker) loadControlManifest() *controlManifest {
	raw, err := os.ReadFile(filepath.Join(c.root, controlManifestRel))
	if err != nil {
		c.add(controlManifestRel, "cannot read the control manifest: %v", err)
		return nil
	}
	var m controlManifest
	if err := decodeStrict(raw, &m); err != nil {
		c.add(controlManifestRel, "does not decode: %v", err)
		return nil
	}
	return &m
}

// checkSeparation keeps the two bundles apart: the runtime manifest lists no control package, and the control manifest
// lists only control packages.
func (c *checker) checkSeparation(m *controlManifest) {
	if rm := c.loadManifest(); rm != nil {
		for _, e := range rm.Rulesets {
			if strings.HasPrefix(e.Package, controlPackagePrefix) {
				c.add(manifestRel, "the runtime bundle lists the control package %s: control rules ship in their own bundle", e.Package)
			}
		}
	}
	if m == nil {
		return
	}
	for _, e := range m.Rulesets {
		if !strings.HasPrefix(e.Package, controlPackagePrefix) {
			c.add(controlManifestRel, "%s/%s: package %s must start with %s", e.Name, e.Version, e.Package, controlPackagePrefix)
		}
	}
}

func (c *checker) checkControlManifest(m *controlManifest, reg *controlRegistry) {
	switch {
	case m.BundleID != controlBundleID:
		c.add(controlManifestRel, "bundle_id must be %q", controlBundleID)
	case m.InputContract != controlInputContract:
		c.add(controlManifestRel, "input_contract must be %q", controlInputContract)
	case !revisionRe.MatchString(m.Revision):
		c.add(controlManifestRel, "revision %q must look like 2026.10.27-1", m.Revision)
	case !commitRe.MatchString(m.GitCommit):
		c.add(controlManifestRel, "git_commit must be 40 hex characters")
	}
	if len(m.Rulesets) == 0 {
		c.add(controlManifestRel, "lists no ruleset")
	}
	seen := map[string]bool{}
	for _, e := range m.Rulesets {
		key := e.Name + "/" + e.Version
		if seen[key] {
			c.add(controlManifestRel, "%s is listed twice", key)
		}
		seen[key] = true
		if _, ok := reg.OutputKeys[e.Name]; !ok {
			c.add(controlReasonsRel, "no output_keys for %s: every control ruleset declares the keys its output may carry", e.Name)
		}
		if !versionRe.MatchString(e.Version) {
			c.add(controlManifestRel, "%s: version %q must look like v1", key, e.Version)
		}
	}
}

func (c *checker) checkControlRuleset(ctx context.Context, e controlEntry, reg *controlRegistry) {
	where := controlRulesetsDirRel + "/" + e.Path
	dir := filepath.Join(c.root, controlRulesetsDirRel, filepath.FromSlash(e.Path))
	policyPath, testPath, examplesPath := filepath.Join(dir, "policy.rego"), filepath.Join(dir, "policy_test.rego"), filepath.Join(dir, controlExamplesFile)

	policySrc, err := os.ReadFile(policyPath)
	if err != nil {
		c.add(where, "missing policy.rego")
		return
	}
	testSrc, testErr := os.ReadFile(testPath)
	if testErr != nil {
		c.add(where, "missing policy_test.rego: a ruleset without tests is not shippable")
	}
	mod, err := ast.ParseModuleWithOpts(policyPath, string(policySrc), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		c.add(where, "policy.rego does not parse: %v", err)
		return
	}
	if got, want := mod.Package.Path.String(), "data."+e.Package; got != want {
		c.add(where, "policy.rego declares package %s, the manifest says %s", got, want)
	}
	if !definesDecision(mod) {
		c.add(where, "policy.rego defines no decision rule: the Landing Zone reads data.<package>.decision")
	}
	c.checkLiterals(where, "policy.rego", mod)
	c.checkControlReasons(where, e, mod, reg)
	if testErr == nil {
		c.runRegoTests(ctx, where, policyPath, string(policySrc), testPath, string(testSrc))
	}
	c.checkControlExamples(ctx, where, e, policyPath, string(policySrc), examplesPath, reg)
}

// checkControlReasons reads every UPPER_SNAKE string and every RULE-ABC-001 string in the policy: each must be registered
// for this ruleset, and each registered one must be used (a stale entry hides a deleted rule).
func (c *checker) checkControlReasons(where string, e controlEntry, mod *ast.Module, reg *controlRegistry) {
	registered, refs, literals := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range reg.Reasons {
		if r.Ruleset == e.Name {
			registered[r.Reason], refs[r.RuleRef] = true, true
		}
	}
	for _, l := range reg.Literals {
		if l.Ruleset == e.Name {
			literals[l.Literal] = true
		}
	}
	for _, r := range reg.Results {
		literals[r] = true
	}
	used := map[string]bool{}
	reported := map[string]bool{}
	ast.WalkTerms(mod, func(t *ast.Term) bool {
		s, ok := t.Value.(ast.String)
		if !ok {
			return false
		}
		str := string(s)
		switch {
		case ruleRefRe.MatchString(str):
			used[str] = true
			if !refs[str] && !reported[str] {
				reported[str] = true
				c.add(where+"/policy.rego", "rule reference %s is not registered for %s in control-reasons.json", str, e.Name)
			}
		case reasonRe.MatchString(str):
			used[str] = true
			if !registered[str] && !literals[str] && !reported[str] {
				reported[str] = true
				c.add(where+"/policy.rego", "%s is not registered for %s in control-reasons.json (as a reason or a literal)", str, e.Name)
			}
		}
		return false
	})
	for _, r := range reg.Reasons {
		if r.Ruleset == e.Name && (!used[r.Reason] || !used[r.RuleRef]) {
			c.add(controlReasonsRel, "%s: registered for %s but no rule uses %s / %s", r.Reason, e.Name, r.Reason, r.RuleRef)
		}
	}
	for _, l := range reg.Literals {
		if l.Ruleset == e.Name && !used[l.Literal] {
			c.add(controlReasonsRel, "literal %s is registered for %s but no rule uses it", l.Literal, e.Name)
		}
	}
}

// checkControlExamples evaluates the ruleset on the inputs it ships and checks what it really returns: the decision must be
// defined, carry only the registered output keys (so nothing can read as an approval), and use only registered reasons
// and rule references.
func (c *checker) checkControlExamples(ctx context.Context, where string, e controlEntry, policyPath, policySrc, examplesPath string, reg *controlRegistry) {
	raw, err := os.ReadFile(examplesPath)
	if err != nil {
		c.add(where, "missing %s: a control ruleset ships examples the gate evaluates", controlExamplesFile)
		return
	}
	var examples []controlExample
	if err := decodeStrict(raw, &examples); err != nil || len(examples) == 0 {
		c.add(where+"/"+controlExamplesFile, "must be a non-empty list of {name, input}: %v", err)
		return
	}
	allowed := map[string]bool{}
	for _, k := range reg.OutputKeys[e.Name] {
		allowed[k] = true
	}
	reasons, refs := map[string]bool{}, map[string]bool{}
	for _, r := range reg.Reasons {
		if r.Ruleset == e.Name {
			reasons[r.Reason], refs[r.RuleRef] = true, true
		}
	}
	for _, ex := range examples {
		rs, err := rego.New(rego.Module(policyPath, policySrc), rego.Query("data."+e.Package+".decision"), rego.Input(ex.Input)).Eval(ctx)
		if err != nil {
			c.add(where+"/"+controlExamplesFile, "example %q: %v", ex.Name, err)
			continue
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			c.add(where+"/"+controlExamplesFile, "example %q: the decision is undefined; an undefined decision would be read as INVALID by the caller, so the rules must answer", ex.Name)
			continue
		}
		out, ok := rs[0].Expressions[0].Value.(map[string]any)
		if !ok {
			c.add(where+"/"+controlExamplesFile, "example %q: the decision is not an object", ex.Name)
			continue
		}
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !allowed[k] {
				c.add(where+"/"+controlExamplesFile, "example %q: output key %q is not one of %v: control output may never carry anything readable as an approval", ex.Name, k, reg.OutputKeys[e.Name])
			}
		}
		for _, field := range []struct {
			key string
			set map[string]bool
		}{{"reason_codes", reasons}, {"rule_refs", refs}} {
			list, _ := out[field.key].([]any)
			for _, v := range list {
				if s, _ := v.(string); !field.set[s] {
					c.add(where+"/"+controlExamplesFile, "example %q: %s %q is not registered for %s", ex.Name, field.key, fmt.Sprint(v), e.Name)
				}
			}
		}
	}
}
