// Package pairtest is the pair conformance gate (PDE architecture document component 11, "Policy Conformance Service", section 13 and the
// section 3 journey). Before a configuration and a policy are activated together, they are tested together: the control rules judge the proposed
// configuration (an accepted limit, a limit that violates the FI class, another bank's configuration), the runtime ruleset then decides under the
// configuration those rules approve (a GUARDED posture still narrows it), and the policy's own mutation and N/N-1 checks are clean. A run that
// passes emits a TESTPACK- record, naming the digests of everything it tested; a run that fails emits none, so there is nothing a release can name.
//
// The values are the spec's (the document's dummy examples), never limits baked into the rules or this package. The regional version skew the
// document asks for is covered at the rules level by the N/N-1 comparison: the older and the newer version answer the same corpus and the newer
// may not silently widen. Skew across live regions is a deployment drill, not something rules can prove.
package pairtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/sspl/sspl-cip-rego-rules/internal/conformance"
)

// Spec is one pair's conformance spec (conformance/pairs/<profile>_<version>.json).
type Spec struct {
	Profile       string        `json:"profile"`
	Version       string        `json:"version"`
	Operation     string        `json:"operation"`
	Description   string        `json:"description"`
	Configuration ConfigSpec    `json:"configuration"`
	Runtime       []RuntimeCase `json:"runtime"`
}

// ConfigSpec is the control-plane half: the profile's field rules, the inherited levels and the proposals to judge.
type ConfigSpec struct {
	Schema map[string]any `json:"schema"`
	L1     map[string]any `json:"l1"`
	L2     map[string]any `json:"l2"`
	Cases  []ConfigCase   `json:"cases"`
}

// ConfigCase is one proposed bank configuration and what the control rules must answer.
type ConfigCase struct {
	Name         string         `json:"name"`
	Bank         string         `json:"bank"`
	MakerBank    string         `json:"maker_bank,omitempty"`    // defaults to Bank
	ProposalBank string         `json:"proposal_bank,omitempty"` // defaults to Bank
	Values       map[string]any `json:"values"`
	WantValid    bool           `json:"want_valid"`
	WantReasons  []string       `json:"want_reasons,omitempty"` // when given, the exact set
}

// RuntimeCase is one request and what the runtime ruleset must decide under an approved configuration.
type RuntimeCase struct {
	Name          string         `json:"name"`
	ValuesFrom    string         `json:"values_from"` // the configuration case whose effective values this runs under
	ValuesExtra   map[string]any `json:"values_extra,omitempty"`
	Posture       map[string]any `json:"posture"`
	Facts         map[string]any `json:"facts"`
	WantResult    string         `json:"want_result,omitempty"`
	WantReason    string         `json:"want_reason,omitempty"`
	WantUndefined bool           `json:"want_undefined,omitempty"` // the rules must give no decision (the PDS records RULE_UNDEFINED)
}

// Record is the TESTPACK- record (format pde-testpack/v1).
type Record struct {
	Format      string  `json:"format"`
	ID          string  `json:"id,omitempty"`
	Status      string  `json:"status"`
	Profile     string  `json:"profile"`
	Version     string  `json:"version"`
	Operation   string  `json:"operation"`
	GeneratedAt string  `json:"generated_at,omitempty"`
	Inputs      Inputs  `json:"inputs"`
	Results     Results `json:"results"`
}

// Inputs are the digests of what was tested together: the policy and the configuration.
type Inputs struct {
	RulesetPolicyDigest  string `json:"ruleset_policy_digest"`
	FactSchemaDigest     string `json:"fact_schema_digest"`
	ControlRulesetDigest string `json:"control_ruleset_digest"`
	ConfigurationDigest  string `json:"configuration_digest"`
	SpecDigest           string `json:"spec_digest"`
}

// Results counts what ran.
type Results struct {
	ConfigurationCases int     `json:"configuration_cases"`
	RuntimeCases       int     `json:"runtime_cases"`
	Mutants            Mutants `json:"mutants"`
	CompatPairs        int     `json:"compat_pairs"`
	UnreviewedWidening int     `json:"unreviewed_widening"`
}

// Mutants is the mutation result of the runtime ruleset and the control ruleset together.
type Mutants struct {
	Total   int `json:"total"`
	Killed  int `json:"killed"`
	Invalid int `json:"invalid"`
}

// Result is one run. Failures name each case or check that failed; Record is a PASS record only when Passed.
type Result struct {
	Passed   bool
	Failures []string
	Record   Record
}

type runtimeEntry struct{ Profile, Version, Package, Path string }

type controlEntry struct{ Name, Version, Package, Path string }

// Run tests the pair the spec describes against the rules under root. An error means the run could not be made (a bad spec, an unknown ruleset);
// a wrong answer is a Failure, not an error. now stamps the record.
func Run(ctx context.Context, root, specPath string, now time.Time) (Result, error) {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return Result{}, fmt.Errorf("pairtest: %w", err)
	}
	var spec Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return Result{}, fmt.Errorf("pairtest: spec: %w", err)
	}
	rt, err := findRuntime(root, spec.Profile, spec.Version)
	if err != nil {
		return Result{}, err
	}
	ctl, err := findControl(root, "validate_configuration")
	if err != nil {
		return Result{}, err
	}
	rtDir := filepath.Join(root, "rulesets", filepath.FromSlash(rt.Path))
	ctlDir := filepath.Join(root, "control", filepath.FromSlash(ctl.Path))
	rtPolicy, err := os.ReadFile(filepath.Join(rtDir, "policy.rego"))
	if err != nil {
		return Result{}, fmt.Errorf("pairtest: %w", err)
	}
	rtSchema, err := os.ReadFile(filepath.Join(rtDir, "fact-schema.json"))
	if err != nil {
		return Result{}, fmt.Errorf("pairtest: %w", err)
	}
	ctlPolicy, err := os.ReadFile(filepath.Join(ctlDir, "policy.rego"))
	if err != nil {
		return Result{}, fmt.Errorf("pairtest: %w", err)
	}
	cfgJSON, err := json.Marshal(spec.Configuration)
	if err != nil {
		return Result{}, err
	}

	rec := Record{
		Format: "pde-testpack/v1", Profile: spec.Profile, Version: spec.Version, Operation: spec.Operation,
		Inputs: Inputs{
			RulesetPolicyDigest: digest(rtPolicy), FactSchemaDigest: digest(rtSchema), ControlRulesetDigest: digest(ctlPolicy),
			ConfigurationDigest: digest(cfgJSON), SpecDigest: digest(raw),
		},
		Results: Results{ConfigurationCases: len(spec.Configuration.Cases), RuntimeCases: len(spec.Runtime)},
	}
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	if len(spec.Configuration.Cases) == 0 || len(spec.Runtime) == 0 {
		fail("a pair needs configuration cases and runtime cases: a testpack that tested none proves nothing")
	}

	// The configuration half: what the control rules say about each proposal, and the effective values of the valid ones.
	effective := map[string]map[string]any{}
	for _, c := range spec.Configuration.Cases {
		out, err := eval(ctx, ctlDir, ctlPolicy, ctl.Package, configInput(spec, c, now))
		if err != nil {
			return Result{}, fmt.Errorf("pairtest: control rules: %w", err)
		}
		if out == nil {
			fail("configuration case %q: the control rules gave no answer; an undefined answer is INVALID, so the rules must answer", c.Name)
			continue
		}
		valid, _ := out["valid"].(bool)
		got := stringSet(out["reason_codes"])
		switch {
		case valid != c.WantValid:
			fail("configuration case %q: valid is %v, the spec expects %v (reasons %v)", c.Name, valid, c.WantValid, sortedKeys(got))
		case c.WantReasons != nil && !sameSet(got, c.WantReasons):
			fail("configuration case %q: reasons %v, the spec expects %v", c.Name, sortedKeys(got), c.WantReasons)
		}
		if valid {
			if eff, ok := out["effective"].(map[string]any); ok {
				effective[c.Name] = eff
			}
		}
	}

	// The runtime half: the policy decides under the configuration the control rules approved.
	for _, c := range spec.Runtime {
		values, ok := effective[c.ValuesFrom]
		if !ok {
			fail("runtime case %q: %q is not a valid configuration case, so there is nothing approved to run the policy under", c.Name, c.ValuesFrom)
			continue
		}
		out, err := eval(ctx, rtDir, rtPolicy, rt.Package, runtimeInput(spec, c, values))
		if err != nil {
			return Result{}, fmt.Errorf("pairtest: runtime ruleset: %w", err)
		}
		if c.WantUndefined {
			if out != nil {
				fail("runtime case %q: the policy decided %v, the spec expects no decision", c.Name, decisionLabel(out))
			}
			continue
		}
		if out == nil {
			fail("runtime case %q: the policy gave no decision, the spec expects %s %s", c.Name, c.WantResult, c.WantReason)
			continue
		}
		result, reason := decisionOf(out)
		if result != c.WantResult || (c.WantReason != "" && reason != c.WantReason) {
			fail("runtime case %q: %s %s, the spec expects %s %s", c.Name, result, reason, c.WantResult, c.WantReason)
		}
	}

	// The policy's own checks: every mutant killed, and no unreviewed widening against the previous version.
	for _, name := range []string{spec.Profile + " " + spec.Version, "CONTROL " + ctl.Name + " " + ctl.Version} {
		rep, err := conformance.MutateRepoOnly(ctx, root, name)
		if err != nil {
			return Result{}, fmt.Errorf("pairtest: %w", err)
		}
		for _, rr := range rep.Rulesets {
			rec.Results.Mutants.Total += rr.Total
			rec.Results.Mutants.Killed += rr.Killed
			rec.Results.Mutants.Invalid += rr.Invalid
		}
		if !rep.OK() {
			fail("mutation: %s leaves a rule its tests do not pin down:\n%s", name, rep.Markdown())
		}
	}
	compat, err := conformance.CompareRepo(ctx, root)
	if err != nil {
		return Result{}, fmt.Errorf("pairtest: %w", err)
	}
	for _, p := range compat.Pairs {
		if p.Profile == spec.Profile && p.To == spec.Version {
			rec.Results.CompatPairs++
			rec.Results.UnreviewedWidening += len(p.Unreviewed)
			for _, w := range p.Unreviewed {
				fail("N and N-1: %s %s to %s widens %q without a review", p.Profile, p.From, p.To, w.Case)
			}
		}
	}
	for _, w := range compat.Stale {
		if w.To == spec.Version {
			fail("N and N-1: a reviewed widening for %q no longer happens", w.Case)
		}
	}

	if len(failures) > 0 {
		rec.Status = "FAIL"
		rec.Inputs, rec.Results = Inputs{}, Results{}
		return Result{Passed: false, Failures: failures, Record: Record{Format: rec.Format, Status: "FAIL", Profile: rec.Profile, Version: rec.Version, Operation: rec.Operation}}, nil
	}
	rec.Status = "PASS"
	rec.GeneratedAt = now.UTC().Format(time.RFC3339)
	rec.ID = testpackID(rec)
	return Result{Passed: true, Record: rec}, nil
}

// testpackID names the record by the profile, the version and a short digest of everything that was tested, so the id identifies the content.
func testpackID(r Record) string {
	h := sha256.New()
	for _, d := range []string{r.Inputs.RulesetPolicyDigest, r.Inputs.FactSchemaDigest, r.Inputs.ControlRulesetDigest, r.Inputs.ConfigurationDigest, r.Inputs.SpecDigest} {
		h.Write([]byte(d + "|"))
	}
	short := strings.TrimPrefix(r.Profile, "BRIDGE-")
	return fmt.Sprintf("TESTPACK-%s-%s-%s-PASS", short, r.Version, hex.EncodeToString(h.Sum(nil))[:8])
}

// WriteRecord writes the PASS record as JSON. A failed run has no record to write, and nothing is created.
func WriteRecord(path string, res Result) error {
	if !res.Passed || res.Record.ID == "" {
		return errors.New("pairtest: a failed pair has no testpack record")
	}
	b, err := json.MarshalIndent(res.Record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func configInput(spec Spec, c ConfigCase, now time.Time) map[string]any {
	makerBank, proposalBank := c.MakerBank, c.ProposalBank
	if makerBank == "" {
		makerBank = c.Bank
	}
	if proposalBank == "" {
		proposalBank = c.Bank
	}
	return map[string]any{
		"ctx": map[string]any{
			"now": now.Format(time.RFC3339), "tz": "Asia/Kolkata", "bank_id": c.Bank, "bundle_revision": "pairtest",
			"maker": map[string]any{"id": "MKR-1", "role": "PRODUCT_OFFICER", "bank_id": makerBank},
		},
		"schema": spec.Configuration.Schema,
		"levels": map[string]any{
			"L1": spec.Configuration.L1, "L2": spec.Configuration.L2,
			"L3": map[string]any{"bank_id": proposalBank, "config_ref": "CFG-PAIRTEST", "values": c.Values},
		},
	}
}

func runtimeInput(spec Spec, c RuntimeCase, values map[string]any) map[string]any {
	merged := map[string]any{}
	for k, v := range values {
		merged[k] = v
	}
	for k, v := range c.ValuesExtra {
		merged[k] = v
	}
	posture := map[string]any{"valid": true}
	for k, v := range c.Posture {
		posture[k] = v
	}
	return map[string]any{
		"ctx": map[string]any{
			"bank_id": "KGB001", "profile": spec.Profile, "operation": spec.Operation, "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata",
			"completions": []any{},
		},
		"facts": c.Facts, "values": merged, "posture": posture,
		"live": map[string]any{"daily_drawn_inr": 0, "found": true}, "customer": "cust-pairtest", "contract": "v1",
	}
}

// eval runs data.<pkg>.decision on input; nil means the decision is undefined.
func eval(ctx context.Context, dir string, policy []byte, pkg string, input map[string]any) (map[string]any, error) {
	rs, err := rego.New(rego.Module(filepath.Join(dir, "policy.rego"), string(policy)), rego.Query("data."+pkg+".decision"), rego.Input(input)).Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	out, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, errors.New("the decision is not an object")
	}
	return out, nil
}

// decisionOf reads the result and the reason of a runtime decision: the seven-result form, or the contract-v1 allow flag.
func decisionOf(out map[string]any) (result, reason string) {
	reason, _ = out["reason"].(string)
	if r, ok := out["result"].(string); ok {
		return r, reason
	}
	if allow, ok := out["allow"].(bool); ok && allow {
		return "PERMIT", reason
	}
	return "DENY", reason
}

func decisionLabel(out map[string]any) string {
	r, why := decisionOf(out)
	return r + " " + why
}

func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok {
			out[s] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameSet(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !got[w] {
			return false
		}
	}
	return true
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func findRuntime(root, profile, version string) (runtimeEntry, error) {
	var m struct {
		Rulesets []runtimeEntry `json:"rulesets"`
	}
	if err := readJSON(filepath.Join(root, "rulesets", "manifest.template.json"), &m); err != nil {
		return runtimeEntry{}, err
	}
	for _, e := range m.Rulesets {
		if e.Profile == profile && e.Version == version {
			return e, nil
		}
	}
	return runtimeEntry{}, fmt.Errorf("pairtest: the rules repository has no ruleset %s %s", profile, version)
}

func findControl(root, name string) (controlEntry, error) {
	var m struct {
		Rulesets []controlEntry `json:"rulesets"`
	}
	if err := readJSON(filepath.Join(root, "control", "manifest.template.json"), &m); err != nil {
		return controlEntry{}, err
	}
	best := controlEntry{}
	for _, e := range m.Rulesets {
		if e.Name == name && (best.Name == "" || e.Version > best.Version) { // v1, v2 ... single digits today; lexical is enough until v10
			best = e
		}
	}
	if best.Name == "" {
		return controlEntry{}, fmt.Errorf("pairtest: the control rules have no %s", name)
	}
	return best, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("pairtest: %w", err)
	}
	return json.Unmarshal(raw, v)
}
