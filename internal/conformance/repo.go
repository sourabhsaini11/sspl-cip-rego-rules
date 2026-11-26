package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

// AcceptedFile is conformance/accepted-mutants.json: mutants a reviewer judged equivalent to the
// original (the change cannot alter any decision), each with the reason. Anything else that survives
// is a rule the tests do not pin down, and fails the gate.
const AcceptedFile = "conformance/accepted-mutants.json"

// Accepted is one reviewed survivor.
type Accepted struct {
	Ruleset  string `json:"ruleset"`   // "BRIDGE-UPI v5"
	Operator string `json:"operator"`  // as the report prints it
	LineText string `json:"line_text"` // the original line, trimmed
	Reason   string `json:"reason"`
}

// RulesetReport is the mutation result of one ruleset.
type RulesetReport struct {
	Ruleset string
	Result
	Unaccepted []Mutant
}

// Report is the mutation result of the repository.
type Report struct {
	Rulesets []RulesetReport
	Stale    []Accepted // accepted entries no survivor matches any more
}

// OK reports whether nothing unreviewed survived and no accepted entry is stale.
func (r Report) OK() bool {
	if len(r.Stale) > 0 {
		return false
	}
	for _, rs := range r.Rulesets {
		if len(rs.Unaccepted) > 0 {
			return false
		}
	}
	return true
}

type manifestRulesets struct {
	Rulesets []struct {
		Profile string `json:"profile"`
		Version string `json:"version"`
		Path    string `json:"path"`
	} `json:"rulesets"`
}

// MutateRepo runs the mutation test over every ruleset in the manifest template under root.
func MutateRepo(ctx context.Context, root string) (Report, error) {
	return MutateRepoOnly(ctx, root, "")
}

// MutateRepoOnly is MutateRepo for one ruleset, named as the report names it ("BRIDGE-UPI v7", or "CONTROL validate_configuration v1"). An empty
// name runs them all. With a name, the reviewed equivalents of the other rulesets are not judged, so they cannot look stale; an unknown name is
// an error rather than an empty pass.
func MutateRepoOnly(ctx context.Context, root, only string) (Report, error) {
	var m manifestRulesets
	if err := readJSON(filepath.Join(root, "rulesets", "manifest.template.json"), &m, false); err != nil {
		return Report{}, err
	}
	// The control-plane family (control/manifest.template.json) is mutation-tested like the runtime rules.
	var cm struct {
		Rulesets []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"rulesets"`
	}
	if _, err := os.Stat(filepath.Join(root, "control", "manifest.template.json")); err == nil {
		if err := readJSON(filepath.Join(root, "control", "manifest.template.json"), &cm, false); err != nil {
			return Report{}, err
		}
	}
	type target struct{ name, dir string }
	var targets []target
	for _, e := range m.Rulesets {
		dir, err := safefs.Join(filepath.Join(root, "rulesets"), e.Path)
		if err != nil {
			return Report{}, fmt.Errorf("conformance: ruleset %s %s: %w", e.Profile, e.Version, err)
		}
		targets = append(targets, target{e.Profile + " " + e.Version, dir})
	}
	for _, e := range cm.Rulesets {
		dir, err := safefs.Join(filepath.Join(root, "control"), e.Path)
		if err != nil {
			return Report{}, fmt.Errorf("conformance: control ruleset %s %s: %w", e.Name, e.Version, err)
		}
		targets = append(targets, target{"CONTROL " + e.Name + " " + e.Version, dir})
	}
	if only != "" {
		kept := targets[:0:0]
		for _, tg := range targets {
			if tg.name == only {
				kept = append(kept, tg)
			}
		}
		if len(kept) == 0 {
			return Report{}, fmt.Errorf("conformance: no ruleset named %q", only)
		}
		targets = kept
	}
	var accepted []Accepted
	if _, err := os.Stat(filepath.Join(root, AcceptedFile)); err == nil {
		var f struct {
			Accepted []Accepted `json:"accepted"`
		}
		if err := readJSON(filepath.Join(root, AcceptedFile), &f, true); err != nil {
			return Report{}, err
		}
		accepted = f.Accepted
		if only != "" {
			own := accepted[:0:0]
			for _, a := range accepted {
				if a.Ruleset == only {
					own = append(own, a)
				}
			}
			accepted = own
		}
	}
	used := make([]bool, len(accepted))
	var rep Report
	for _, tg := range targets {
		dir := tg.dir
		pol, err := safefs.ReadFile(filepath.Join(dir, "policy.rego"))
		if err != nil {
			return Report{}, err
		}
		tst, err := safefs.ReadFile(filepath.Join(dir, "policy_test.rego"))
		if err != nil {
			return Report{}, err
		}
		name := tg.name
		res, err := Run(ctx, string(pol), string(tst))
		if err != nil {
			return Report{}, fmt.Errorf("%s: %w", name, err)
		}
		rr := RulesetReport{Ruleset: name, Result: res}
		for _, s := range res.Survivors {
			s.Ruleset = name
			idx := matchAccepted(accepted, s)
			if idx >= 0 {
				used[idx] = true
				continue
			}
			rr.Unaccepted = append(rr.Unaccepted, s)
		}
		rep.Rulesets = append(rep.Rulesets, rr)
	}
	for i, a := range accepted {
		if !used[i] {
			rep.Stale = append(rep.Stale, a)
		}
	}
	return rep, nil
}

func matchAccepted(list []Accepted, m Mutant) int {
	for i, a := range list {
		if a.Ruleset == m.Ruleset && a.Operator == m.Operator && a.LineText == m.LineText {
			return i
		}
	}
	return -1
}

func readJSON(path string, v any, strict bool) error {
	raw, err := safefs.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Markdown renders the mutation report.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Mutation testing of the rulesets\n\n")
	b.WriteString("| Ruleset | Mutants | Killed | Not compiling | Survived | Unreviewed |\n|---|---|---|---|---|---|\n")
	for _, rs := range r.Rulesets {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", rs.Ruleset, rs.Total, rs.Killed, rs.Invalid, len(rs.Survivors), len(rs.Unaccepted))
	}
	for _, rs := range r.Rulesets {
		if len(rs.Unaccepted) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s: survivors no test catches\n\n", rs.Ruleset)
		sort.Slice(rs.Unaccepted, func(i, j int) bool { return rs.Unaccepted[i].Line < rs.Unaccepted[j].Line })
		for _, s := range rs.Unaccepted {
			fmt.Fprintf(&b, "- line %d `%s`: `%s`\n", s.Line, s.Operator, s.LineText)
		}
	}
	for _, a := range r.Stale {
		fmt.Fprintf(&b, "\nStale accepted entry: %s %s `%s`\n", a.Ruleset, a.Operator, a.LineText)
	}
	return b.String()
}
