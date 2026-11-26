package rulesgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

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
	dir, err := safefs.Join(filepath.Join(root, "rulesets"), rs.Path)
	if err != nil {
		return s, fmt.Errorf("rulesgen: ruleset %s %s: %w", rs.Profile, rs.Version, err)
	}
	if err := readJSON(filepath.Join(dir, "fact-schema.json"), &s); err != nil {
		return s, fmt.Errorf("rulesgen: ruleset %s %s: %w", rs.Profile, rs.Version, err)
	}
	return s, nil
}

func stageRulesets(root string, m *manifestFile, files map[string][]byte) error {
	for _, r := range m.Rulesets {
		dir, err := safefs.Join(filepath.Join(root, "rulesets"), r.Path)
		if err != nil {
			return fmt.Errorf("rulesgen: %w", err)
		}
		for _, name := range []string{"policy.rego", "fact-schema.json"} {
			b, err := safefs.ReadFile(filepath.Join(dir, name))
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
		b, err := safefs.ReadFile(filepath.Join(root, filepath.FromSlash(dir), "rule.rego"))
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
	raw, err := safefs.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// readStrict decodes one JSON document and refuses unknown keys and trailing data.
func readStrict(path string, v any) error {
	raw, err := safefs.ReadFile(path)
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
