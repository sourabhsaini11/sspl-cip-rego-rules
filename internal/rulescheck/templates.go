package rulescheck

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

// checkTemplates inspects templates/<rule_type>/: rule.rego, rule_test.rego and template.json.
// A template is generic Rego for one catalogue rule type; the PDS runs it for every profile
// a binding names it for, so the checks are the ruleset checks, once per template.
func (c *checker) checkTemplates(ctx context.Context) error {
	dirs, err := os.ReadDir(filepath.Join(c.root, templatesRel))
	if err != nil {
		return nil // no templates directory: a P0-only repository
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		c.checkTemplate(ctx, d.Name())
	}
	return nil
}

func (c *checker) checkTemplate(ctx context.Context, name string) {
	ruleType := strings.ToUpper(name)
	where := "template " + ruleType
	if !templateRe.MatchString(name) {
		c.add(templatesRel+"/"+name, "directory name must be the rule type in lower snake case")
		return
	}
	c.tplTypes[ruleType] = true
	dir := filepath.Join(c.root, templatesRel, name)
	rulePath, testPath := filepath.Join(dir, "rule.rego"), filepath.Join(dir, "rule_test.rego")

	c.checkTemplateMeta(where, ruleType, filepath.Join(dir, "template.json"))

	src, err := safefs.ReadFile(rulePath)
	if err != nil {
		c.add(where, "missing rule.rego")
		return
	}
	testSrc, testErr := safefs.ReadFile(testPath)
	if testErr != nil {
		c.add(where, "missing rule_test.rego: a template without tests is not shippable")
	}
	mod, err := ast.ParseModuleWithOpts(rulePath, string(src), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		c.add(where, "rule.rego does not parse: %v", err)
		return
	}
	if got, want := mod.Package.Path.String(), "data."+templatePackageFor(ruleType); got != want {
		c.add(where, "rule.rego declares package %s, the bundle expects %s", got, want)
	}
	if !definesDecision(mod) {
		c.add(where, "rule.rego defines no decision rule: the PDS reads data.<package>.decision")
	}
	c.checkLiterals(where, "rule.rego", mod, "")
	if c.reg != nil {
		registered := map[string]bool{}
		for _, r := range c.reg.TemplateReasons {
			if r.RuleType == ruleType {
				registered[r.Reason] = true
			}
		}
		c.walkReasons(where+"/rule.rego", ruleType, "for template "+ruleType, mod, registered, c.tplUsed, nil, map[string]bool{})
	}
	if testErr == nil {
		c.runRegoTests(ctx, where, rulePath, string(src), testPath, string(testSrc))
	}
}

// templatePackageFor is the package a template must declare, the PDS's own rule:
// "AMOUNT_PER_TXN" -> "cip.pde.template.amount_per_txn".
func templatePackageFor(ruleType string) string {
	return "cip.pde.template." + strings.ToLower(ruleType)
}

func (c *checker) checkTemplateMeta(where, ruleType, path string) {
	raw, err := safefs.ReadFile(path)
	if err != nil {
		c.add(where, "missing template.json: it says which facts the template reads")
		return
	}
	var m templateMeta
	if err := decodeStrict(raw, &m); err != nil {
		c.add(where+"/template.json", "not valid template metadata: %v", err)
		return
	}
	if m.RuleType != ruleType {
		c.add(where+"/template.json", "rule_type %q must be %q, the directory's rule type", m.RuleType, ruleType)
	}
	names := make([]string, 0, len(m.RequiresFacts))
	for n := range m.RequiresFacts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if t := m.RequiresFacts[n]; t != "string" && t != "int" && t != "bool" {
			c.add(where+"/template.json", "required fact %q has unknown type %q", n, t)
		}
	}
}

// checkStaleTemplates reports template reasons registered for a rule type that has no
// template, or that no template produces.
func (c *checker) checkStaleTemplates() {
	if c.reg == nil {
		return
	}
	for _, r := range c.reg.TemplateReasons {
		switch {
		case !c.tplTypes[r.RuleType]:
			c.add(reasonsRel, "template %s/%s: registered for a rule type that has no template", r.RuleType, r.Reason)
		case !c.tplUsed[r.RuleType+"|"+r.Reason]:
			c.add(reasonsRel, "template %s/%s: registered but never produced by its template", r.RuleType, r.Reason)
		}
	}
}

func (c *checker) checkStale(m *manifest) {
	if c.reg == nil {
		return
	}
	profiles := map[string]bool{}
	for _, e := range m.Rulesets {
		profiles[e.Profile] = true
	}
	for _, r := range c.reg.Reasons {
		switch {
		case !profiles[r.Profile]:
			c.add(reasonsRel, "%s/%s: registered for a profile that is not in the manifest", r.Profile, r.Reason)
		case !c.used[r.Profile+"|"+r.Reason]:
			c.add(reasonsRel, "%s/%s: registered but never produced by its rules", r.Profile, r.Reason)
		}
	}
	for _, l := range c.reg.Literals {
		switch {
		case !profiles[l.Profile]:
			c.add(reasonsRel, "literal %s/%s: registered for a profile that is not in the manifest", l.Profile, l.Literal)
		case !c.litUsed[l.Profile+"|"+l.Literal]:
			c.add(reasonsRel, "literal %s/%s: registered but never used by its rules", l.Profile, l.Literal)
		}
	}
}
