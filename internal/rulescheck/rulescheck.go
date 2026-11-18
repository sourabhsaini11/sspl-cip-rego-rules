// Package rulescheck is the bundle pipeline's gate: it decides whether the rules in this
// repository may be signed and handed to the Policy Decision Service (PDS).
//
// The PDS owns the contract (docs/rules-contract.md in its repository) and enforces what it
// can at load time: the input-contract version, the manifest shape, the MAC, a lower
// revision. It does not look inside the rules. These checks do, because the PDS design
// puts them in the pipeline (PDS LLD 02-B §5: no literal limits in rules; 03-B §3: reasons
// are registered with the bundle and an unregistered one is not rejected at run time).
package rulescheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
)

// SupportedInputContract is the input-contract version these rules are written for. The PDS
// builds exactly one version and refuses a bundle that declares another. Change it only
// together with the rules and the PDS release that moves to the new contract.
const SupportedInputContract = "v1"

const (
	manifestRel  = "rulesets/manifest.template.json"
	reasonsRel   = "contract/reasons.json"
	templatesRel = "templates"
)

var (
	profileRe  = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,63}$`)
	versionRe  = regexp.MustCompile(`^v[1-9][0-9]*$`)
	revisionRe = regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}-\d{1,9}$`)
	commitRe   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reasonRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	ruleTypeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	templateRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

	// allowedLiterals are the only numbers a rule may contain: 0 and 1 (counting, "at least
	// one rupee") and the two hours of the local night window. Anything else is a limit and
	// belongs in the bank's signed state, not in Git.
	allowedLiterals = map[string]bool{"0": true, "1": true, "6": true, "22": true}

	factTypes = map[string]bool{"string": true, "int": true, "bool": true, "enum": true}
)

// Problem is one reason the rules must not ship.
type Problem struct{ Where, What string }

func (p Problem) String() string { return p.Where + ": " + p.What }

type manifest struct {
	BundleID      string  `json:"bundle_id"`
	Revision      string  `json:"revision"`
	InputContract string  `json:"input_contract"`
	GitCommit     string  `json:"git_commit"`
	Rulesets      []entry `json:"rulesets"`
}

type entry struct {
	Profile         string `json:"profile"`
	Version         string `json:"version"`
	Package         string `json:"package"`
	Path            string `json:"path"`
	CompatibleSince string `json:"compatible_since"`
}

type registry struct {
	RegistryVersion    int        `json:"registry_version"`
	Description        string     `json:"description"`
	Reasons            []regEntry `json:"reasons"`
	TemplateReasons    []tplEntry `json:"template_reasons"`
	Literals           []litEntry `json:"literals"`
	ReservedForPDS     []string   `json:"reserved_for_pds"`
	AllowedReasonCodes []string   `json:"allowed_reason_codes"`
}

// tplEntry registers a reason a P1 template may return, per rule type rather than per profile:
// a template runs for every profile it is bound to.
type tplEntry struct {
	RuleType   string `json:"rule_type"`
	Reason     string `json:"reason"`
	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code"`
}

// templateMeta is templates/<rule_type>/template.json: which facts the template reads, so a
// binding can be refused for a ruleset whose fact schema does not declare them.
type templateMeta struct {
	RuleType      string            `json:"rule_type"`
	RequiresFacts map[string]string `json:"requires_facts"`
}

// litEntry registers an UPPER_SNAKE string a ruleset uses that is not a reason: an operation code it
// switches on, or an obligation it asks the enforcement point to complete. The gate reads every
// UPPER_SNAKE string as a reason, so these are told apart by registration (docs/rules-contract.md,
// section 6). A fact's enum values need no registration: they come from the ruleset's fact schema.
type litEntry struct {
	Profile string `json:"profile"`
	Literal string `json:"literal"`
	Kind    string `json:"kind"`
}

// literalKinds are what a registered literal may be.
var literalKinds = map[string]bool{"OPERATION": true, "OBLIGATION": true, "POSTURE": true}

type regEntry struct {
	Profile    string `json:"profile"`
	Reason     string `json:"reason"`
	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code"`
}

type checker struct {
	root     string
	problems []Problem
	reg      *registry
	reserved map[string]bool
	codes    map[string]bool
	used     map[string]bool // profile|reason produced by some ruleset
	litUsed  map[string]bool // profile|literal used by some ruleset
	tplUsed  map[string]bool // rule_type|reason produced by some template
	tplTypes map[string]bool // rule types that have a template directory
}

func (c *checker) add(where, format string, args ...any) {
	c.problems = append(c.problems, Problem{Where: where, What: fmt.Sprintf(format, args...)})
}

// Check inspects the rulesets and the contract under root. A returned error means the check
// itself could not run (the context was cancelled); anything wrong with the rules is a Problem.
func Check(ctx context.Context, root string) ([]Problem, error) {
	c := &checker{root: root, reserved: map[string]bool{}, codes: map[string]bool{}, used: map[string]bool{}, litUsed: map[string]bool{}, tplUsed: map[string]bool{}, tplTypes: map[string]bool{}}
	c.loadRegistry()
	m := c.loadManifest()
	if m != nil {
		c.checkManifest(m)
		c.checkOrphans(m)
		for _, e := range m.Rulesets {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.checkRuleset(ctx, e)
		}
		c.checkStale(m)
	}
	if err := c.checkTemplates(ctx); err != nil {
		return nil, err
	}
	c.checkStaleTemplates()
	return c.problems, ctx.Err()
}

// ---- registry ---------------------------------------------------------------------------

func (c *checker) loadRegistry() {
	raw, err := os.ReadFile(filepath.Join(c.root, reasonsRel))
	if err != nil {
		c.add(reasonsRel, "cannot read the reason registry: %v", err)
		return
	}
	var r registry
	if err := decodeStrict(raw, &r); err != nil {
		c.add(reasonsRel, "not a valid reason registry: %v", err)
		return
	}
	c.reg = &r
	for _, s := range r.ReservedForPDS {
		c.reserved[s] = true
	}
	for _, s := range r.AllowedReasonCodes {
		c.codes[s] = true
	}
	if len(c.codes) == 0 {
		c.add(reasonsRel, "allowed_reason_codes is empty")
	}
	seen := map[string]bool{}
	for _, e := range r.Reasons {
		who := e.Profile + "/" + e.Reason
		switch {
		case !profileRe.MatchString(e.Profile):
			c.add(reasonsRel, "%s: profile is not a valid profile name", who)
		case !reasonRe.MatchString(e.Reason):
			c.add(reasonsRel, "%s: reason must be UPPER_SNAKE_CASE", who)
		case c.reserved[e.Reason]:
			c.add(reasonsRel, "%s: reason is reserved for the PDS and cannot be registered for rules", who)
		}
		if seen[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seen[who] = true
		c.checkVerdict(who, e.Verdict, e.ReasonCode)
	}
	seenLit := map[string]bool{}
	for _, e := range r.Literals {
		who := "literal " + e.Profile + "/" + e.Literal
		switch {
		case !profileRe.MatchString(e.Profile):
			c.add(reasonsRel, "%s: profile is not a valid profile name", who)
		case !reasonRe.MatchString(e.Literal):
			c.add(reasonsRel, "%s: literal must be UPPER_SNAKE_CASE", who)
		case !literalKinds[e.Kind]:
			c.add(reasonsRel, "%s: kind must be OPERATION, OBLIGATION or POSTURE, got %q", who, e.Kind)
		case c.reserved[e.Literal] || results[e.Literal]:
			c.add(reasonsRel, "%s: a reserved reason or a result cannot be a literal", who)
		}
		if seenLit[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seenLit[who] = true
		for _, rr := range r.Reasons {
			if rr.Profile == e.Profile && rr.Reason == e.Literal {
				c.add(reasonsRel, "%s: is also registered as a reason; it is one or the other", who)
			}
		}
	}
	seenTpl := map[string]bool{}
	for _, e := range r.TemplateReasons {
		who := "template " + e.RuleType + "/" + e.Reason
		switch {
		case !ruleTypeRe.MatchString(e.RuleType):
			c.add(reasonsRel, "%s: rule_type must be UPPER_SNAKE_CASE", who)
		case !reasonRe.MatchString(e.Reason):
			c.add(reasonsRel, "%s: reason must be UPPER_SNAKE_CASE", who)
		case c.reserved[e.Reason]:
			c.add(reasonsRel, "%s: reason is reserved for the PDS and cannot be registered for rules", who)
		}
		if seenTpl[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seenTpl[who] = true
		c.checkVerdict(who, e.Verdict, e.ReasonCode)
	}
}

// results are the seven results of the PDE architecture document (section 8). A v2 ruleset
// returns one as a string, so the reason scan must not mistake it for a reason.
var results = map[string]bool{
	"PERMIT": true, "DENY": true, "STEP_UP": true, "NEED_EVIDENCE": true,
	"REFER": true, "DEFER_UNAVAILABLE": true, "INDETERMINATE": true,
}

// checkVerdict validates a registered reason's verdict and class. The verdict is one of the
// seven results, or ALLOW or REJECT for a contract v1 ruleset. Only a permit (PERMIT, ALLOW)
// carries no reason_code; every other verdict needs one of the four platform classes.
func (c *checker) checkVerdict(who, verdict, code string) {
	switch {
	case verdict == "ALLOW" || verdict == "PERMIT":
		if code != "" {
			c.add(reasonsRel, "%s: a %s reason carries no reason_code, got %q", who, verdict, code)
		}
	case verdict == "REJECT" || results[verdict]:
		if !c.codes[code] {
			c.add(reasonsRel, "%s: a %s reason needs a reason_code from allowed_reason_codes, got %q", who, verdict, code)
		}
	default:
		c.add(reasonsRel, "%s: verdict must be one of the seven results, or ALLOW or REJECT, got %q", who, verdict)
	}
}

// ---- manifest ---------------------------------------------------------------------------

func (c *checker) loadManifest() *manifest {
	raw, err := os.ReadFile(filepath.Join(c.root, manifestRel))
	if err != nil {
		c.add(manifestRel, "cannot read the manifest: %v", err)
		return nil
	}
	var m manifest
	if err := decodeStrict(raw, &m); err != nil {
		c.add(manifestRel, "not a valid manifest: %v", err)
		return nil
	}
	return &m
}

func (c *checker) checkManifest(m *manifest) {
	if m.BundleID == "" {
		c.add(manifestRel, "bundle_id is empty")
	}
	if !revisionRe.MatchString(m.Revision) {
		c.add(manifestRel, "revision %q is not yyyy.mm.dd-n", m.Revision)
	}
	if m.InputContract != SupportedInputContract {
		c.add(manifestRel, "input_contract %q is not the contract the PDS builds (%s): the PDS would refuse this bundle",
			m.InputContract, SupportedInputContract)
	}
	if m.GitCommit != "" && !commitRe.MatchString(m.GitCommit) {
		c.add(manifestRel, "git_commit %q is not a 40-character commit id", m.GitCommit)
	}
	if len(m.Rulesets) == 0 {
		c.add(manifestRel, "no rulesets")
	}
	paths, versions := map[string]bool{}, map[string]bool{}
	for _, e := range m.Rulesets {
		who := e.Profile + "@" + e.Version
		if !profileRe.MatchString(e.Profile) {
			c.add(manifestRel, "%s: profile is not a valid profile name", who)
		}
		if !versionRe.MatchString(e.Version) {
			c.add(manifestRel, "%s: version must look like v5", who)
		}
		if want := packageFor(e.Profile, e.Version); e.Package != want {
			c.add(manifestRel, "%s: package %q must be %q", who, e.Package, want)
		}
		if e.Path == "" || !filepath.IsLocal(e.Path) {
			c.add(manifestRel, "%s: path %q must be a relative path inside rulesets/", who, e.Path)
		}
		if e.CompatibleSince != "" && !versionRe.MatchString(e.CompatibleSince) {
			c.add(manifestRel, "%s: compatible_since %q must look like v4", who, e.CompatibleSince)
		}
		if paths[e.Path] {
			c.add(manifestRel, "%s: path %q is used by two rulesets", who, e.Path)
		}
		if versions[who] {
			c.add(manifestRel, "%s: listed twice", who)
		}
		paths[e.Path], versions[who] = true, true
	}
}

// packageFor is the Rego package a profile and version must declare, the PDS's own rule:
// ("BRIDGE-UPI","v5") -> "cip.pde.bridge_upi.v5".
func packageFor(profile, version string) string {
	return "cip.pde." + strings.ToLower(strings.ReplaceAll(profile, "-", "_")) + "." + version
}

// checkOrphans finds ruleset directories that exist on disk but are not in the manifest: they
// would never be signed, so nobody would notice they were not shipping.
func (c *checker) checkOrphans(m *manifest) {
	listed := map[string]bool{}
	for _, e := range m.Rulesets {
		listed[filepath.ToSlash(filepath.Clean(e.Path))] = true
	}
	base := filepath.Join(c.root, "rulesets")
	profiles, err := os.ReadDir(base)
	if err != nil {
		return // loadManifest already reported an unreadable rulesets directory
	}
	for _, p := range profiles {
		if !p.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(base, p.Name()))
		if err != nil {
			continue
		}
		for _, v := range versions {
			rel := p.Name() + "/" + v.Name()
			if v.IsDir() && !listed[rel] {
				c.add("rulesets/"+rel, "ruleset directory is not in the manifest, so it would never ship")
			}
		}
	}
}

// ---- one ruleset ------------------------------------------------------------------------

func (c *checker) checkRuleset(ctx context.Context, e entry) {
	where := "rulesets/" + e.Path
	dir := filepath.Join(c.root, "rulesets", filepath.FromSlash(e.Path))
	policyPath, testPath, schemaPath := filepath.Join(dir, "policy.rego"), filepath.Join(dir, "policy_test.rego"), filepath.Join(dir, "fact-schema.json")

	policySrc, err := os.ReadFile(policyPath)
	if err != nil {
		c.add(where, "missing policy.rego")
		return
	}
	testSrc, testErr := os.ReadFile(testPath)
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
	c.checkLiterals(where, "policy.rego", mod)
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

func (c *checker) checkLiterals(where, file string, mod *ast.Module) {
	reported := map[string]bool{}
	ast.WalkTerms(mod, func(t *ast.Term) bool {
		if n, ok := t.Value.(ast.Number); ok {
			lit := n.String()
			if !allowedLiterals[lit] && !reported[lit] {
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
	raw, err := os.ReadFile(filepath.Join(c.root, "rulesets", filepath.FromSlash(e.Path), "fact-schema.json"))
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

// ---- templates (P1) ----------------------------------------------------------------------

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

	src, err := os.ReadFile(rulePath)
	if err != nil {
		c.add(where, "missing rule.rego")
		return
	}
	testSrc, testErr := os.ReadFile(testPath)
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
	c.checkLiterals(where, "rule.rego", mod)
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
	raw, err := os.ReadFile(path)
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

// checkFactSchema applies the PDS's own validation of fact-schema.json: closed keys, at least
// one field, a known type, enum values only on enum fields.
func (c *checker) checkFactSchema(where, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		c.add(where, "missing fact-schema.json: the PDS refuses a ruleset without one")
		return
	}
	var s struct {
		Fields map[string]struct {
			Type     string   `json:"type"`
			Required bool     `json:"required"`
			Enum     []string `json:"enum"`
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

// decodeStrict decodes one JSON document and refuses unknown keys and trailing data, as the
// PDS does for the files it reads.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the document")
	}
	return nil
}
