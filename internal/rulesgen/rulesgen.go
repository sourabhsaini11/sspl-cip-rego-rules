// Package rulesgen is the Landing Zone side of the second rule source (P1): it turns a
// published profile into bindings, and assembles an unsigned bundle directory that the
// signing step takes as its source (docs/rego-rule-sources.md in the PDS repository).
//
// A binding says which reviewed template applies to which operation, and which key of the
// bank's signed state holds its limit. It never carries the limit, so generating bindings
// writes no policy data and no new code: the only Rego in the bundle is what Git reviewed.
package rulesgen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Options names the inputs of one generation.
type Options struct {
	Root      string   // the repository root: rulesets/, templates/
	Catalogue string   // catalogue export: one row per rule, applies_to already split
	Profiles  []string // published-profile files
	Out       string   // directory to create; must not exist or must be empty
	// PolicyDataOut, when set, receives the bindings as a separate policy-data artefact (policy-data.manifest.template.json
	// and bindings/...), and the bundle in Out then carries none. A published profile is bank configuration: the PDE
	// architecture document (section 13) says a configuration-only change needs a new snapshot and never a new bundle, so
	// the same rules and templates always give the same bundle bytes. Empty keeps the legacy layout, with the bindings in
	// the bundle manifest, until the PDS loads policy data (plan Task 10). It must differ from Out and be empty too.
	PolicyDataOut string
}

// Skip is a configured rule that produced no binding, and why.
type Skip struct{ RuleID, Why string }

// Report says what a generation did.
type Report struct {
	Bound   int
	Skipped []Skip
}

type catalogueFile struct {
	Rules []catalogueRule `json:"rules"`
}

type catalogueRule struct {
	FieldPath string   `json:"field_path"`
	RuleType  string   `json:"rule_type"`
	AppliesTo []string `json:"applies_to"`
}

type profileFile struct {
	Profile string   `json:"profile"`
	Fields  []string `json:"fields"`
	// Versions limits the ruleset versions the rules are bound to. Absent means every version of the
	// profile in the manifest: a bank pinned to an older version must get its configured rules too
	// (docs/policy-binding.md in the PDS repository, B-9).
	Versions []string `json:"versions,omitempty"`
}

type binding struct {
	RuleID     string   `json:"rule_id"`
	RuleType   string   `json:"rule_type"`
	Operations []string `json:"operations"`
	ValueKey   string   `json:"value_key"`
}

type manifestFile struct {
	BundleID      string          `json:"bundle_id"`
	Revision      string          `json:"revision"`
	InputContract string          `json:"input_contract"`
	GitCommit     string          `json:"git_commit,omitempty"`
	Rulesets      []rulesetEntry  `json:"rulesets"`
	Templates     []templateEntry `json:"templates,omitempty"`
	Bindings      []bindingsEntry `json:"bindings,omitempty"`
}

type rulesetEntry struct {
	Profile         string `json:"profile"`
	Version         string `json:"version"`
	Package         string `json:"package"`
	Path            string `json:"path"`
	CompatibleSince string `json:"compatible_since,omitempty"`
}

type templateEntry struct {
	RuleType string `json:"rule_type"`
	Package  string `json:"package"`
	Path     string `json:"path"`
}

type bindingsEntry struct {
	Profile string `json:"profile"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type templateMeta struct {
	RuleType      string            `json:"rule_type"`
	RequiresFacts map[string]string `json:"requires_facts"`
}

type factSchema struct {
	Fields map[string]struct {
		Type string `json:"type"`
	} `json:"fields"`
}

var operationRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Generate builds the unsigned bundle directory. Nothing is written unless every input is
// valid, so a refused generation leaves Out exactly as it was.
func Generate(o Options) (Report, error) {
	if err := checkOut(o.Out); err != nil {
		return Report{}, err
	}
	if o.PolicyDataOut != "" {
		if sameDir(o.Out, o.PolicyDataOut) {
			return Report{}, errors.New("rulesgen: the policy-data directory must differ from the bundle directory")
		}
		if err := checkOut(o.PolicyDataOut); err != nil {
			return Report{}, err
		}
	}
	cat, err := readCatalogue(o.Catalogue)
	if err != nil {
		return Report{}, err
	}
	m, err := readManifest(o.Root)
	if err != nil {
		return Report{}, err
	}
	templates, err := readTemplates(o.Root)
	if err != nil {
		return Report{}, err
	}

	files := map[string][]byte{}
	if err := stageRulesets(o.Root, m, files); err != nil {
		return Report{}, err
	}
	stageTemplates(o.Root, templates, m, files)

	var rep Report
	for _, pf := range o.Profiles {
		if err := bindProfile(o.Root, pf, cat, m, templates, files, &rep); err != nil {
			return Report{}, err
		}
	}
	sort.Slice(m.Bindings, func(i, j int) bool {
		a, b := m.Bindings[i], m.Bindings[j]
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return versionNumber(a.Version) < versionNumber(b.Version)
	})
	var policyFiles map[string][]byte
	if o.PolicyDataOut != "" {
		if policyFiles, err = splitPolicyData(m, files); err != nil {
			return Report{}, err
		}
	}
	mb, err := marshal(m)
	if err != nil {
		return Report{}, err
	}
	files["manifest.template.json"] = mb
	if err := writeAll(o.Out, files); err != nil {
		return Report{}, err
	}
	if policyFiles != nil {
		return rep, writeAll(o.PolicyDataOut, policyFiles)
	}
	return rep, nil
}

// policyDataManifest is policy-data.manifest.template.json: the unsigned list of the binding files and their digests.
// The signing step stamps the revision and the MAC, as it does for the bundle; the revision moves with the
// configuration, not with the rules.
type policyDataManifest struct {
	Format        string              `json:"format"`
	BundleID      string              `json:"bundle_id"`
	InputContract string              `json:"input_contract"`
	Bindings      []policyDataBinding `json:"bindings"`
}

type policyDataBinding struct {
	Profile string `json:"profile"`
	Version string `json:"version"`
	Path    string `json:"path"`
	Digest  string `json:"digest"`
}

// splitPolicyData moves the binding files and their manifest entries out of the bundle's files and manifest into a
// policy-data artefact, and returns that artefact's files.
func splitPolicyData(m *manifestFile, files map[string][]byte) (map[string][]byte, error) {
	pd := policyDataManifest{Format: "pde-policy-data/v1", BundleID: "pde-policy-data", InputContract: m.InputContract, Bindings: []policyDataBinding{}}
	out := map[string][]byte{}
	for _, b := range m.Bindings {
		raw, ok := files[b.Path]
		if !ok {
			return nil, fmt.Errorf("rulesgen: bindings file %s was not staged", b.Path)
		}
		sum := sha256.Sum256(raw)
		pd.Bindings = append(pd.Bindings, policyDataBinding{Profile: b.Profile, Version: b.Version, Path: b.Path, Digest: "sha256:" + hex.EncodeToString(sum[:])})
		out[b.Path] = raw
		delete(files, b.Path)
	}
	m.Bindings = nil
	mb, err := marshal(pd)
	if err != nil {
		return nil, err
	}
	out["policy-data.manifest.template.json"] = mb
	return out, nil
}

func sameDir(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	return errA == nil && errB == nil && aa == bb
}

func bindProfile(root, path string, cat map[string]catalogueRule, m *manifestFile, templates map[string]templateMeta, files map[string][]byte, rep *Report) error {
	var p profileFile
	if err := readStrict(path, &p); err != nil {
		return fmt.Errorf("rulesgen: profile %s: %w", path, err)
	}
	targets, err := targetVersions(m, p)
	if err != nil {
		return err
	}
	for _, rs := range targets {
		if err := bindVersion(root, p, rs, cat, m, templates, files, rep); err != nil {
			return err
		}
	}
	return nil
}

// targetVersions returns the ruleset versions a profile's rules are bound to: the versions it names,
// each of which must exist, or every version of the profile in the manifest.
func targetVersions(m *manifestFile, p profileFile) ([]rulesetEntry, error) {
	var all []rulesetEntry
	for _, r := range m.Rulesets {
		if r.Profile == p.Profile {
			all = append(all, r)
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("rulesgen: profile %s has no ruleset in the manifest", p.Profile)
	}
	sort.Slice(all, func(i, j int) bool { return versionNumber(all[i].Version) < versionNumber(all[j].Version) })
	if len(p.Versions) == 0 {
		return all, nil
	}
	var out []rulesetEntry
	seen := map[string]bool{}
	for _, v := range p.Versions {
		if seen[v] {
			return nil, fmt.Errorf("rulesgen: profile %s lists version %s twice", p.Profile, v)
		}
		seen[v] = true
		found := false
		for _, r := range all {
			if r.Version == v {
				out, found = append(out, r), true
			}
		}
		if !found {
			return nil, fmt.Errorf("rulesgen: profile %s names version %s, which the manifest does not have", p.Profile, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return versionNumber(out[i].Version) < versionNumber(out[j].Version) })
	return out, nil
}

func bindVersion(root string, p profileFile, rs rulesetEntry, cat map[string]catalogueRule, m *manifestFile, templates map[string]templateMeta, files map[string][]byte, rep *Report) error {
	schema, err := readSchema(root, rs)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var rules []binding
	for _, field := range p.Fields {
		if seen[field] {
			return fmt.Errorf("rulesgen: profile %s lists %s twice", p.Profile, field)
		}
		seen[field] = true
		row, ok := cat[field]
		if !ok {
			return fmt.Errorf("rulesgen: profile %s configures %s, which is not in the catalogue", p.Profile, field)
		}
		tpl, ok := templates[row.RuleType]
		if !ok {
			rep.skip(field, "no template for rule type "+row.RuleType)
			continue
		}
		if class := operationClass(row.AppliesTo); class != "" {
			rep.skip(field, fmt.Sprintf("applies to an operation class, not an operation (%q)", class))
			continue
		}
		if err := checkFacts(p.Profile, rs, schema, field, tpl); err != nil {
			return err
		}
		rules = append(rules, binding{RuleID: field, RuleType: row.RuleType, Operations: row.AppliesTo, ValueKey: field})
	}
	if len(rules) == 0 {
		return nil
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].RuleType != rules[j].RuleType {
			return rules[i].RuleType < rules[j].RuleType
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	rel := "bindings/" + snake(p.Profile) + "/" + rs.Version + ".json"
	b, err := marshal(map[string]any{"rules": rules})
	if err != nil {
		return err
	}
	files[rel] = b
	m.Bindings = append(m.Bindings, bindingsEntry{Profile: rs.Profile, Version: rs.Version, Path: rel})
	rep.Bound += len(rules)
	return nil
}

// skip records a configured rule that produced no binding. A rule skipped on several versions is
// reported once.
func (r *Report) skip(rule, why string) {
	for _, s := range r.Skipped {
		if s.RuleID == rule && s.Why == why {
			return
		}
	}
	r.Skipped = append(r.Skipped, Skip{RuleID: rule, Why: why})
}

// checkFacts refuses a binding whose template reads a fact the target ruleset's closed fact
// schema does not declare: such a rule could never judge, so the operation would be rejected
// for every request.
func checkFacts(profile string, rs rulesetEntry, schema factSchema, field string, tpl templateMeta) error {
	names := make([]string, 0, len(tpl.RequiresFacts))
	for n := range tpl.RequiresFacts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, ok := schema.Fields[n]
		switch {
		case !ok:
			return fmt.Errorf("rulesgen: %s cannot be bound to %s %s: %s reads fact %s (%s), which the ruleset does not declare",
				field, profile, rs.Version, tpl.RuleType, n, tpl.RequiresFacts[n])
		case f.Type != tpl.RequiresFacts[n]:
			return fmt.Errorf("rulesgen: %s cannot be bound to %s %s: fact %s is %s there, %s reads it as %s",
				field, profile, rs.Version, n, f.Type, tpl.RuleType, tpl.RequiresFacts[n])
		}
	}
	return nil
}

func operationClass(ops []string) string {
	for _, op := range ops {
		if !operationRe.MatchString(op) {
			return op
		}
	}
	return ""
}

func versionNumber(v string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(v, "v"), 10, 32)
	return n
}

func snake(profile string) string { return strings.ToLower(strings.ReplaceAll(profile, "-", "_")) }

// ---- inputs -----------------------------------------------------------------------------

func readCatalogue(path string) (map[string]catalogueRule, error) {
	var f catalogueFile
	if err := readStrict(path, &f); err != nil {
		return nil, fmt.Errorf("rulesgen: catalogue %s: %w", path, err)
	}
	out := make(map[string]catalogueRule, len(f.Rules))
	for _, r := range f.Rules {
		if _, dup := out[r.FieldPath]; dup {
			return nil, fmt.Errorf("rulesgen: catalogue lists %s twice", r.FieldPath)
		}
		out[r.FieldPath] = r
	}
	return out, nil
}

func readManifest(root string) (*manifestFile, error) {
	var m manifestFile
	p := filepath.Join(root, "rulesets", "manifest.template.json")
	if err := readStrict(p, &m); err != nil {
		return nil, fmt.Errorf("rulesgen: %w", err)
	}
	if len(m.Templates) > 0 || len(m.Bindings) > 0 {
		return nil, errors.New("rulesgen: the manifest template must not list templates or bindings; they are generated")
	}
	return &m, nil
}

func readTemplates(root string) (map[string]templateMeta, error) {
	out := map[string]templateMeta{}
	dirs, err := os.ReadDir(filepath.Join(root, "templates"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("rulesgen: %w", err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		var meta templateMeta
		if err := readStrict(filepath.Join(root, "templates", d.Name(), "template.json"), &meta); err != nil {
			return nil, fmt.Errorf("rulesgen: template %s: %w", d.Name(), err)
		}
		if strings.ToLower(meta.RuleType) != d.Name() {
			return nil, fmt.Errorf("rulesgen: template %s declares rule type %s", d.Name(), meta.RuleType)
		}
		out[meta.RuleType] = meta
	}
	return out, nil
}

func readSchema(root string, rs rulesetEntry) (factSchema, error) {
	var s factSchema
	if err := readJSON(filepath.Join(root, "rulesets", filepath.FromSlash(rs.Path), "fact-schema.json"), &s); err != nil {
		return s, fmt.Errorf("rulesgen: ruleset %s %s: %w", rs.Profile, rs.Version, err)
	}
	return s, nil
}

// ---- output -----------------------------------------------------------------------------

func stageRulesets(root string, m *manifestFile, files map[string][]byte) error {
	for _, r := range m.Rulesets {
		for _, name := range []string{"policy.rego", "fact-schema.json"} {
			b, err := os.ReadFile(filepath.Join(root, "rulesets", filepath.FromSlash(r.Path), name))
			if err != nil {
				return fmt.Errorf("rulesgen: %w", err)
			}
			files[r.Path+"/"+name] = b
		}
	}
	return nil
}

func stageTemplates(root string, templates map[string]templateMeta, m *manifestFile, files map[string][]byte) {
	types := make([]string, 0, len(templates))
	for rt := range templates {
		types = append(types, rt)
	}
	sort.Strings(types)
	for _, rt := range types {
		dir := "templates/" + strings.ToLower(rt)
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir), "rule.rego"))
		if err != nil {
			continue // the gate reports a template without rule.rego; the bundle reader refuses it
		}
		files[dir+"/rule.rego"] = b
		m.Templates = append(m.Templates, templateEntry{RuleType: rt, Package: "cip.pde.template." + strings.ToLower(rt), Path: dir})
	}
}

func checkOut(out string) error {
	if out == "" {
		return errors.New("rulesgen: an output directory is required")
	}
	entries, err := os.ReadDir(out)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("rulesgen: %w", err)
	case len(entries) > 0:
		return fmt.Errorf("rulesgen: %s is not empty", out)
	}
	return nil
}

func writeAll(out string, files map[string][]byte) error {
	rels := make([]string, 0, len(files))
	for r := range files {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		dst := filepath.Join(out, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return fmt.Errorf("rulesgen: %w", err)
		}
		if err := os.WriteFile(dst, files[rel], 0o600); err != nil {
			return fmt.Errorf("rulesgen: %w", err)
		}
	}
	return nil
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// readStrict decodes one JSON document and refuses unknown keys and trailing data.
func readStrict(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
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
