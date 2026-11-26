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
	"regexp"
	"strings"
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

	// devOnlyLiterals are numbers ONE named ruleset may contain on top of allowedLiterals. TEMPORARY, dev test only:
	// BRIDGE-BALANCE-ENQUIRY-E2E v2 has its night window at 15:00 to 15:50 so the night rule can be exercised in the afternoon.
	// Every other ruleset is still held to allowedLiterals. Remove the entry with the v2 stand-in.
	devOnlyLiterals = map[string]map[string]bool{
		"bridge_balance_enquiry_e2e/v2": {"15": true, "50": true},
	}

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
	Profile         string   `json:"profile"`
	Version         string   `json:"version"`
	Package         string   `json:"package"`
	Path            string   `json:"path"`
	CompatibleSince string   `json:"compatible_since"`
	RiskClass       string   `json:"risk_class"`
	TenancyReasons  []string `json:"tenancy_reasons"`
}

// riskClasses are the classes the PDS accepts in a signed manifest (PDS docs/rules-contract.md, section 4.5).
var riskClasses = map[string]bool{"CONSEQUENTIAL": true, "STANDARD": true, "LOW_RISK": true}

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
	// Tenancy marks a reason that means a request crossed a tenant boundary (PDE architecture document section 30: cross-tenant denials are always traced). The manifest
	// carries it to the PDS; checkTenancy makes the two agree.
	Tenancy bool `json:"tenancy"`
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
	c.checkSafeReasons()
	return c.problems, ctx.Err()
}

// packageFor is the Rego package a profile and version must declare, the PDS's own rule:
// ("BRIDGE-UPI","v5") -> "cip.pde.bridge_upi.v5".
func packageFor(profile, version string) string {
	return "cip.pde." + strings.ToLower(strings.ReplaceAll(profile, "-", "_")) + "." + version
}

// unreadable says why a required file could not be used: "missing" when it is not there, otherwise the reason (too large, a
// symbolic link, not a regular file), so a refused file is not reported as an absent one.
func unreadable(name string, err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "missing " + name
	}
	return fmt.Sprintf("cannot read %s: %v", name, err)
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
