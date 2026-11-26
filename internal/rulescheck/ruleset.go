package rulescheck

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

func (c *checker) checkRuleset(ctx context.Context, e entry) {
	where := "rulesets/" + e.Path
	dir, err := safefs.Join(filepath.Join(c.root, "rulesets"), e.Path)
	if err != nil {
		c.add(where, "path %q is not inside rulesets/", e.Path)
		return
	}
	policyPath, testPath, schemaPath := filepath.Join(dir, "policy.rego"), filepath.Join(dir, "policy_test.rego"), filepath.Join(dir, "fact-schema.json")

	policySrc, err := safefs.ReadFile(policyPath)
	if err != nil {
		c.add(where, "%s", unreadable("policy.rego", err))
		return
	}
	testSrc, testErr := safefs.ReadFile(testPath)
	if testErr != nil {
		c.add(where, "missing policy_test.rego: a ruleset without tests is not shippable")
	}
	c.checkFactSchema(where, schemaPath)

	mod, err := ast.ParseModuleWithOpts(policyPath, string(policySrc), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		c.add(where, "policy.rego does not parse: %v", err)
		return
	}
	if got, want := mod.Package.Path.String(), "data."+e.Package; got != want {
		c.add(where, "policy.rego declares package %s, the manifest says %s", got, want)
	}
	if !definesDecision(mod) {
		c.add(where, "policy.rego defines no decision rule: the PDS reads data.<package>.decision")
	}
	c.checkLiterals(where, "policy.rego", mod, e.Path)
	c.checkReasons(where, e, mod)
	if testErr == nil {
		c.runRegoTests(ctx, where, policyPath, string(policySrc), testPath, string(testSrc))
	}
}

func definesDecision(mod *ast.Module) bool {
	for _, r := range mod.Rules {
		if r.Head.Ref().String() == "decision" {
			return true
		}
	}
	return false
}

func (c *checker) checkLiterals(where, file string, mod *ast.Module, rulesetPath string) {
	reported := map[string]bool{}
	ast.WalkTerms(mod, func(t *ast.Term) bool {
		if n, ok := t.Value.(ast.Number); ok {
			lit := n.String()
			if !allowedLiterals[lit] && !devOnlyLiterals[rulesetPath][lit] && !reported[lit] {
				reported[lit] = true
				c.add(where+"/"+file, "literal %s looks like policy data; limits belong in input.values (signed bank state), not in Git", lit)
			}
		}
		return false
	})
}

// checkReasons reads every UPPER_SNAKE string in the policy as a reason and every CIP-POL-
// string as a reason code. Today that is exact: the policies hold no other such strings. A
// rule that needs one must register it or the check reports it, which is the point.
func (c *checker) checkReasons(where string, e entry, mod *ast.Module) {
	if c.reg == nil {
		return
	}
	registered := map[string]bool{}
	for _, r := range c.reg.Reasons {
		if r.Profile == e.Profile {
			registered[r.Reason] = true
		}
	}
	literals := map[string]bool{}
	for _, l := range c.reg.Literals {
		if l.Profile == e.Profile {
			literals[l.Literal] = true
		}
	}
	for _, v := range c.enumValues(e) { // a fact's enum values are not reasons
		literals[v] = true
	}
	c.walkReasons(where+"/policy.rego", e.Profile, "for "+e.Profile, mod, registered, c.used, literals, c.litUsed)
}

// enumValues returns every enum value the ruleset's fact schema declares.
func (c *checker) enumValues(e entry) []string {
	dir, err := safefs.Join(filepath.Join(c.root, "rulesets"), e.Path)
	if err != nil {
		return nil
	}
	raw, err := safefs.ReadFile(filepath.Join(dir, "fact-schema.json"))
	if err != nil {
		return nil
	}
	var s struct {
		Fields map[string]struct {
			Enum []string `json:"enum"`
		} `json:"fields"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	var out []string
	for _, f := range s.Fields {
		out = append(out, f.Enum...)
	}
	return out
}

// walkReasons is the reason scan shared by rulesets and templates. owner is the profile or
// rule type, registered is what that owner may return, and used records what it does.
func (c *checker) walkReasons(file, owner, label string, mod *ast.Module, registered, used, literals, litUsed map[string]bool) {
	reported := map[string]bool{}
	ast.WalkTerms(mod, func(t *ast.Term) bool {
		s, ok := t.Value.(ast.String)
		if !ok || reported[string(s)] {
			return false
		}
		lit := string(s)
		switch {
		case strings.HasPrefix(lit, "CIP-POL-"):
			if !c.codes[lit] {
				reported[lit] = true
				c.add(file, "reason_code %q is not one of the allowed CIP-POL codes", lit)
			}
		case results[lit]:
			// a result, not a reason
		case literals[lit]:
			litUsed[owner+"|"+lit] = true // an operation, an obligation or a fact's enum value
		case reasonRe.MatchString(lit):
			reported[lit] = true
			switch {
			case c.reserved[lit]:
				c.add(file, "reason %s is reserved for the PDS; a rule must not return it", lit)
			case !registered[lit]:
				c.add(file, "reason %s is not registered %s in %s", lit, label, reasonsRel)
			default:
				used[owner+"|"+lit] = true
			}
		}
		return false
	})
}

// maxAgeKeyRe is the PDS's rule for the configuration key that bounds a fact source's age.
var maxAgeKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// checkFactSchema applies the PDS's own validation of fact-schema.json: closed keys, at least
// one field, a known type, enum values only on enum fields, and the provenance keys (a fact that needs
// a source, and the configuration key that bounds its age).
func (c *checker) checkFactSchema(where, path string) {
	raw, err := safefs.ReadFile(path)
	if err != nil {
		c.add(where, "missing fact-schema.json: the PDS refuses a ruleset without one")
		return
	}
	var s struct {
		Fields map[string]struct {
			Type           string   `json:"type"`
			Required       bool     `json:"required"`
			Enum           []string `json:"enum"`
			SourceRequired bool     `json:"source_required"`
			MaxAgeKey      string   `json:"max_age_key"`
		} `json:"fields"`
	}
	if err := decodeStrict(raw, &s); err != nil {
		c.add(where+"/fact-schema.json", "not a valid fact schema: %v", err)
		return
	}
	if len(s.Fields) == 0 {
		c.add(where+"/fact-schema.json", "no fields")
	}
	names := make([]string, 0, len(s.Fields))
	for n := range s.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := s.Fields[n]
		switch {
		case !factTypes[f.Type]:
			c.add(where+"/fact-schema.json", "field %q has unknown type %q", n, f.Type)
		case f.Type == "enum" && len(f.Enum) == 0:
			c.add(where+"/fact-schema.json", "enum field %q has no values", n)
		case f.Type != "enum" && len(f.Enum) > 0:
			c.add(where+"/fact-schema.json", "field %q has enum values but type %q", n, f.Type)
		case f.MaxAgeKey != "" && !f.SourceRequired:
			c.add(where+"/fact-schema.json", "fact %q names a freshness window but does not require a source", n)
		case f.MaxAgeKey != "" && !maxAgeKeyRe.MatchString(f.MaxAgeKey):
			c.add(where+"/fact-schema.json", "fact %q: max_age_key must be a lower_snake_case configuration key", n)
		}
	}
}

// runRegoTests runs policy_test.rego against policy.rego with OPA's own test runner, strictly
// compiled, exactly as the PDS's own suite does.
func (c *checker) runRegoTests(ctx context.Context, where, policyPath, policySrc, testPath, testSrc string) {
	mods := map[string]*ast.Module{}
	for path, src := range map[string]string{policyPath: policySrc, testPath: testSrc} {
		mod, err := ast.ParseModuleWithOpts(path, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			c.add(where, "%s does not parse: %v", filepath.Base(path), err)
			return
		}
		mods[path] = mod
	}
	compiler := ast.NewCompiler().WithStrict(true)
	if compiler.Compile(mods); compiler.Failed() {
		c.add(where, "Rego does not compile: %v", compiler.Errors)
		return
	}
	ch, err := tester.NewRunner().SetCompiler(compiler).SetStore(inmem.New()).SetModules(mods).RunTests(ctx, nil)
	if err != nil {
		c.add(where, "Rego tests could not run: %v", err)
		return
	}
	ran := 0
	for r := range ch {
		ran++
		switch {
		case r.Error != nil:
			c.add(where, "Rego test %s failed: %v", r.Name, r.Error)
		case r.Fail:
			c.add(where, "Rego test %s failed: assertion failed", r.Name)
		case r.Skip:
			c.add(where, "Rego test %s was skipped", r.Name)
		}
	}
	if ran == 0 {
		c.add(where, "policy_test.rego contains no tests")
	}
}

// checkTenancy makes the manifest's tenancy_reasons and the registry's tenancy flags agree, per profile and for every version of it. The PDS trusts the signed
// manifest, so a disagreement would silently stop a cross-tenant denial being traced. A tenancy reason must be registered for the profile and be a denial.
func (c *checker) checkTenancy(m *manifest) {
	if c.reg == nil {
		return
	}
	flagged := map[string]map[string]bool{} // profile -> reasons flagged in the registry
	known := map[string]map[string]string{} // profile -> reason -> verdict
	for _, r := range c.reg.Reasons {
		if known[r.Profile] == nil {
			known[r.Profile] = map[string]string{}
		}
		known[r.Profile][r.Reason] = r.Verdict
		if !r.Tenancy {
			continue
		}
		if r.Verdict != "DENY" && r.Verdict != "REJECT" {
			c.add(reasonsRel, "%s/%s: tenancy is set on a reason whose verdict is %s: only a DENY can be a cross-tenant denial", r.Profile, r.Reason, r.Verdict)
		}
		if flagged[r.Profile] == nil {
			flagged[r.Profile] = map[string]bool{}
		}
		flagged[r.Profile][r.Reason] = true
	}
	for _, e := range m.Rulesets {
		who := e.Profile + "@" + e.Version
		declared := map[string]bool{}
		for _, r := range e.TenancyReasons {
			declared[r] = true
			if _, ok := known[e.Profile][r]; !ok {
				c.add(manifestRel, "%s: tenancy reason %s is not a registered reason of %s", who, r, e.Profile)
			} else if !flagged[e.Profile][r] {
				c.add(manifestRel, "%s: tenancy reason %s is declared here but the registry does not flag it as tenancy", who, r)
			}
		}
		for r := range flagged[e.Profile] {
			if !declared[r] {
				c.add(manifestRel, "%s: the registry flags %s as a tenancy reason but this ruleset does not declare it, so the PDS would not trace that denial", who, r)
			}
		}
	}
}
