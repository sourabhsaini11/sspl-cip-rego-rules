package rulesgen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

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
