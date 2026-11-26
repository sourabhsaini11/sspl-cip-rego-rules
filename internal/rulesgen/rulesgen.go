// Package rulesgen is the Landing Zone side of the second rule source (P1): it turns a
// published profile into bindings, and assembles an unsigned bundle directory that the
// signing step takes as its source (docs/rego-rule-sources.md in the PDS repository).
//
// A binding says which reviewed template applies to which operation, and which key of the
// bank's signed state holds its limit. It never carries the limit, so generating bindings
// writes no policy data and no new code: the only Rego in the bundle is what Git reviewed.
package rulesgen

import (
	"errors"
	"regexp"
	"sort"
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
	Profile         string   `json:"profile"`
	Version         string   `json:"version"`
	Package         string   `json:"package"`
	Path            string   `json:"path"`
	CompatibleSince string   `json:"compatible_since,omitempty"`
	RiskClass       string   `json:"risk_class,omitempty"`
	TenancyReasons  []string `json:"tenancy_reasons,omitempty"`
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
		if err := addSafeReasons(o.Root, policyFiles); err != nil {
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
