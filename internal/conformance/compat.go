package conformance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

// The N and N-1 comparison (PDE architecture document, section 33: "N/N-1 compatibility"). For every
// profile with more than one ruleset version, a corpus of inputs is run through each adjacent pair
// and the answers compared. A newer version may be stricter than the one before it. It may not
// become more permissive on any corpus input unless a reviewer listed that exact change, with a
// reason: a bank pinned to the older version and a bank on the newer one must not see a request
// silently allowed by the upgrade.

// CompatDir holds one corpus file per profile.
const CompatDir = "conformance/compat"

// Widening is a reviewed, intended loosening between two versions on one corpus case.
type Widening struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Case   string `json:"case"`
	Reason string `json:"reason"`
}

type corpusCase struct {
	Name   string         `json:"name"`
	Now    string         `json:"now"`
	Facts  map[string]any `json:"facts"`
	Values map[string]any `json:"values"`
	Live   map[string]any `json:"live"`
}

type corpusFile struct {
	Profile         string       `json:"profile"`
	Operation       string       `json:"operation"`
	Cases           []corpusCase `json:"cases"`
	AllowedWidening []Widening   `json:"allowed_widening"`
}

// Outcome is what one ruleset answered for one input.
type Outcome struct {
	Defined bool
	Result  string
	Reason  string
}

func (o Outcome) String() string {
	if !o.Defined {
		return "UNDEFINED"
	}
	if o.Reason == "" {
		return o.Result
	}
	return o.Result + "/" + o.Reason
}

// restrictiveness ranks results from least to most restrictive, the PDS's own order. A decision the
// rules leave undefined is recorded as a DENY, so it ranks as one.
var restrictiveness = map[string]int{
	"PERMIT": 0, "STEP_UP": 1, "NEED_EVIDENCE": 2, "REFER": 3, "DENY": 4, "DEFER_UNAVAILABLE": 5, "INDETERMINATE": 6,
}

func (o Outcome) rank() int {
	if !o.Defined {
		return restrictiveness["DENY"]
	}
	if r, ok := restrictiveness[o.Result]; ok {
		return r
	}
	return restrictiveness["INDETERMINATE"]
}

// Change is one corpus case whose answer differs between two versions.
type Change struct {
	Case     string
	Old, New Outcome
}

// PairReport compares one adjacent pair of versions.
type PairReport struct {
	Profile, From, To string
	Same, Narrowed    int
	Changes           []Change // narrowed, or different at the same restrictiveness
	Reviewed          []Change // widenings a reviewer listed
	Unreviewed        []Change // widenings nobody listed
}

// CompatReport is the comparison for the repository.
type CompatReport struct {
	Pairs []PairReport
	Stale []Widening // reviewed widenings that no longer happen
}

// OK reports whether every widening was reviewed and no review is stale.
func (r CompatReport) OK() bool {
	if len(r.Stale) > 0 {
		return false
	}
	for _, p := range r.Pairs {
		if len(p.Unreviewed) > 0 {
			return false
		}
	}
	return true
}

// CompareRepo runs the comparison for every profile in the manifest with more than one version.
func CompareRepo(ctx context.Context, root string) (CompatReport, error) {
	var m struct {
		Rulesets []struct {
			Profile string `json:"profile"`
			Version string `json:"version"`
			Package string `json:"package"`
			Path    string `json:"path"`
		} `json:"rulesets"`
	}
	if err := readJSON(filepath.Join(root, "rulesets", "manifest.template.json"), &m, false); err != nil {
		return CompatReport{}, err
	}
	type version struct{ v, pkg, path string }
	byProfile := map[string][]version{}
	for _, e := range m.Rulesets {
		byProfile[e.Profile] = append(byProfile[e.Profile], version{e.Version, e.Package, e.Path})
	}
	profiles := make([]string, 0, len(byProfile))
	for p := range byProfile {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)

	var rep CompatReport
	for _, profile := range profiles {
		vs := byProfile[profile]
		if len(vs) < 2 {
			continue
		}
		sort.Slice(vs, func(i, j int) bool { return number(vs[i].v) < number(vs[j].v) })
		path := filepath.Join(root, CompatDir, strings.ToLower(strings.ReplaceAll(profile, "-", "_"))+".json")
		var c corpusFile
		if err := readJSON(path, &c, true); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return CompatReport{}, fmt.Errorf("conformance: %s has %d versions and no corpus at %s", profile, len(vs), filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))))
			}
			return CompatReport{}, err
		}
		if c.Profile != profile || c.Operation == "" || len(c.Cases) == 0 {
			return CompatReport{}, fmt.Errorf("conformance: the corpus for %s must name the profile, an operation and cases", profile)
		}
		used := make([]bool, len(c.AllowedWidening))
		for i := 1; i < len(vs); i++ {
			old, cur := vs[i-1], vs[i]
			pr := PairReport{Profile: profile, From: old.v, To: cur.v}
			for _, cs := range c.Cases {
				a, err := evaluate(ctx, root, old.path, old.pkg, profile, c.Operation, cs)
				if err != nil {
					return CompatReport{}, fmt.Errorf("conformance: %s %s: %w", profile, old.v, err)
				}
				b, err := evaluate(ctx, root, cur.path, cur.pkg, profile, c.Operation, cs)
				if err != nil {
					return CompatReport{}, fmt.Errorf("conformance: %s %s: %w", profile, cur.v, err)
				}
				ch := Change{Case: cs.Name, Old: a, New: b}
				switch {
				case a == b:
					pr.Same++
				case b.rank() < a.rank():
					if idx := reviewed(c.AllowedWidening, old.v, cur.v, cs.Name); idx >= 0 {
						used[idx] = true
						pr.Reviewed = append(pr.Reviewed, ch)
					} else {
						pr.Unreviewed = append(pr.Unreviewed, ch)
					}
				case b.rank() > a.rank():
					pr.Narrowed++
					pr.Changes = append(pr.Changes, ch)
				default:
					pr.Same++ // the same restrictiveness, a different reason: not a loosening
					pr.Changes = append(pr.Changes, ch)
				}
			}
			rep.Pairs = append(rep.Pairs, pr)
		}
		for i, w := range c.AllowedWidening {
			if !used[i] {
				rep.Stale = append(rep.Stale, w)
			}
		}
	}
	return rep, nil
}

func number(v string) int { n, _ := strconv.Atoi(strings.TrimPrefix(v, "v")); return n }

func reviewed(list []Widening, from, to, name string) int {
	for i, w := range list {
		if w.From == from && w.To == to && w.Case == name {
			return i
		}
	}
	return -1
}

// evaluate runs the ruleset's decision rule on the case.
func evaluate(ctx context.Context, root, path, pkg, profile, operation string, cs corpusCase) (Outcome, error) {
	src, err := os.ReadFile(filepath.Join(root, "rulesets", filepath.FromSlash(path), "policy.rego"))
	if err != nil {
		return Outcome{}, err
	}
	now := cs.Now
	if now == "" {
		now = "2026-10-15T14:30:00+05:30"
	}
	live := map[string]any{"daily_drawn_inr": 0, "found": true}
	for k, v := range cs.Live {
		live[k] = v
	}
	input := map[string]any{
		"ctx":     map[string]any{"bank_id": "KGB001", "profile": profile, "operation": operation, "now": now, "tz": "Asia/Kolkata"},
		"facts":   cs.Facts,
		"values":  cs.Values,
		"posture": map[string]any{"operating": "NORMAL", "valid": true},
		"live":    live, "customer": "cust", "contract": "v1",
	}
	rs, err := rego.New(rego.Module("policy.rego", string(src)), rego.Query("data."+pkg+".decision"), rego.Input(input)).Eval(ctx)
	if err != nil {
		return Outcome{}, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Outcome{}, nil
	}
	d, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Outcome{}, fmt.Errorf("decision is not an object")
	}
	out := Outcome{Defined: true}
	out.Reason, _ = d["reason"].(string)
	switch {
	case d["result"] != nil:
		out.Result, _ = d["result"].(string)
	default:
		if allow, _ := d["allow"].(bool); allow {
			out.Result = "PERMIT"
		} else {
			out.Result = "DENY"
		}
	}
	return out, nil
}

// Markdown renders the comparison.
func (r CompatReport) Markdown() string {
	var b strings.Builder
	b.WriteString("# N and N-1 compatibility\n\n")
	b.WriteString("| Profile | From | To | Same | Narrowed | Reviewed widening | Unreviewed widening |\n|---|---|---|---|---|---|---|\n")
	for _, p := range r.Pairs {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n", p.Profile, p.From, p.To, p.Same, p.Narrowed, len(p.Reviewed), len(p.Unreviewed))
	}
	for _, p := range r.Pairs {
		if len(p.Changes)+len(p.Reviewed)+len(p.Unreviewed) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s %s to %s\n\n", p.Profile, p.From, p.To)
		for _, c := range p.Unreviewed {
			fmt.Fprintf(&b, "- **WIDENED, not reviewed** `%s`: %s to %s\n", c.Case, c.Old, c.New)
		}
		for _, c := range p.Reviewed {
			fmt.Fprintf(&b, "- widened, reviewed `%s`: %s to %s\n", c.Case, c.Old, c.New)
		}
		for _, c := range p.Changes {
			fmt.Fprintf(&b, "- changed `%s`: %s to %s\n", c.Case, c.Old, c.New)
		}
	}
	for _, w := range r.Stale {
		fmt.Fprintf(&b, "\nStale review: %s to %s on `%s` no longer widens (%s)\n", w.From, w.To, w.Case, w.Reason)
	}
	return b.String()
}
