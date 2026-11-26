package pairtest_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/pairtest"
)

// The pair conformance gate (PDE architecture document component 11, section 13 and the section 3 journey): before a pair is activated, the
// configuration and the policy are tested together: the control rules judge the proposed configuration, the runtime ruleset decides under the
// configuration they approve, and the policy's mutation and N/N-1 checks are clean. A passing run emits a TESTPACK- record; a failing one emits none.

const (
	repoRoot = "../.."
	specRel  = "conformance/pairs/bridge_upi_v7.json"
)

var when = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

// testpackID is the same pattern the PDS release accepts.
var testpackID = regexp.MustCompile(`^TESTPACK-[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)

func run(t *testing.T, spec string) pairtest.Result {
	t.Helper()
	res, err := pairtest.Run(context.Background(), repoRoot, spec, when)
	require.NoError(t, err)
	return res
}

// editSpec writes a changed copy of the checked-in spec and returns its path.
func editSpec(t *testing.T, f func(map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, specRel))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	f(m)
	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "spec.json")
	require.NoError(t, os.WriteFile(p, out, 0o600))
	return p
}

func TestTheCheckedInUPIPairPasses(t *testing.T) {
	res := run(t, filepath.Join(repoRoot, specRel))

	require.True(t, res.Passed, "%v", res.Failures)
	require.Empty(t, res.Failures)
	require.Equal(t, 5, res.Record.Results.ConfigurationCases)
	require.Equal(t, 7, res.Record.Results.RuntimeCases)
	require.Equal(t, res.Record.Results.Mutants.Total-res.Record.Results.Mutants.Invalid, res.Record.Results.Mutants.Killed, "every mutant killed")
	require.Positive(t, res.Record.Results.Mutants.Total)
	require.Zero(t, res.Record.Results.UnreviewedWidening)
	require.Positive(t, res.Record.Results.CompatPairs, "the N and N-1 comparison ran, which is the version-skew check at the rules level")
}

func TestThePassRecordNamesWhatWasTestedAndIsAnIdThePDSAccepts(t *testing.T) {
	rec := run(t, filepath.Join(repoRoot, specRel)).Record

	require.Equal(t, "pde-testpack/v1", rec.Format)
	require.Equal(t, "PASS", rec.Status)
	require.Equal(t, "BRIDGE-UPI", rec.Profile)
	require.Equal(t, "v7", rec.Version)
	require.True(t, testpackID.MatchString(rec.ID), rec.ID)
	require.Regexp(t, `^TESTPACK-UPI-v7-[0-9a-f]{8}-PASS$`, rec.ID)
	require.Equal(t, when.Format(time.RFC3339), rec.GeneratedAt)
	for name, d := range map[string]string{
		"ruleset policy": rec.Inputs.RulesetPolicyDigest, "fact schema": rec.Inputs.FactSchemaDigest, "control ruleset": rec.Inputs.ControlRulesetDigest,
		"configuration": rec.Inputs.ConfigurationDigest, "spec": rec.Inputs.SpecDigest,
	} {
		require.Regexp(t, `^sha256:[0-9a-f]{64}$`, d, name)
	}
}

func TestTheRecordIsDeterministicAndChangesWithTheConfiguration(t *testing.T) {
	a := run(t, filepath.Join(repoRoot, specRel)).Record
	b := run(t, filepath.Join(repoRoot, specRel)).Record
	require.Equal(t, a, b)

	other := editSpec(t, func(m map[string]any) {
		m["configuration"].(map[string]any)["l2"].(map[string]any)["per_txn_limit_inr"] = 55000 // another FI class limit that every case still agrees with
	})
	c := run(t, other).Record
	require.NotEqual(t, a.ID, c.ID, "another configuration is another testpack")
	require.NotEqual(t, a.Inputs.ConfigurationDigest, c.Inputs.ConfigurationDigest)
	require.Equal(t, a.Inputs.RulesetPolicyDigest, c.Inputs.RulesetPolicyDigest, "the policy is the same bytes")
}

func TestAConfigurationCaseThatTheControlRulesAnswerDifferentlyFailsThePair(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) {
		cases := m["configuration"].(map[string]any)["cases"].([]any)
		cases[1].(map[string]any)["want_valid"] = true // 60,000 is not valid
	})

	res := run(t, spec)

	require.False(t, res.Passed)
	require.Contains(t, res.Failures[0], "60,000")
}

func TestARuntimeCaseThatThePolicyAnswersDifferentlyFailsThePair(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) {
		rt := m["runtime"].([]any)
		rt[0].(map[string]any)["want_result"] = "PERMIT" // the GUARDED payment is denied
	})

	res := run(t, spec)

	require.False(t, res.Passed)
	require.Contains(t, res.Failures[0], "GUARDED")
}

func TestAnUndefinedDecisionIsAFailureWhereADecisionWasExpected(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) {
		rt := m["runtime"].([]any)
		rt[1].(map[string]any)["posture"] = map[string]any{"operating": "RESTRICTED"} // undefined, not the expected PERMIT
	})

	res := run(t, spec)

	require.False(t, res.Passed)
}

func TestARuntimeCaseRunsOnTheConfigurationTheControlRulesApprove(t *testing.T) {
	// The pair: a runtime case names the configuration case whose effective values it runs under. If that configuration is not valid there is
	// nothing the policy may be tested with, and the pair fails rather than running on invented limits.
	spec := editSpec(t, func(m map[string]any) {
		m["runtime"].([]any)[0].(map[string]any)["values_from"] = "a 60,000 bank limit violates the FI class limit (L2)"
	})

	res := run(t, spec)

	require.False(t, res.Passed)
	require.Contains(t, res.Failures[0], "not a valid configuration")
}

func TestARuntimeCaseThatNamesNoSuchConfigurationFails(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) { m["runtime"].([]any)[0].(map[string]any)["values_from"] = "no such case" })
	res := run(t, spec)
	require.False(t, res.Passed)
}

func TestAFailedPairCarriesNoPassRecord(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) { m["runtime"].([]any)[0].(map[string]any)["want_result"] = "PERMIT" })

	res := run(t, spec)

	require.False(t, res.Passed)
	require.Empty(t, res.Record.ID, "a failed run has no TESTPACK-: there is nothing for a release to name")
	require.NotEqual(t, "PASS", res.Record.Status)
}

func TestASpecForARulesetThatDoesNotExistIsAnError(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) { m["version"] = "v99" })
	_, err := pairtest.Run(context.Background(), repoRoot, spec, when)
	require.ErrorContains(t, err, "v99")
}

func TestAnUnknownFieldInTheSpecIsRefused(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) { m["wat"] = 1 })
	_, err := pairtest.Run(context.Background(), repoRoot, spec, when)
	require.Error(t, err)
}

func TestAPairWithNoCasesIsNotAPass(t *testing.T) {
	spec := editSpec(t, func(m map[string]any) { m["runtime"] = []any{} })
	res := run(t, spec)
	require.False(t, res.Passed, "a testpack that tested no runtime decision proves nothing")
}

func TestWriteRecordWritesAPassAndRefusesAFail(t *testing.T) {
	pass := run(t, filepath.Join(repoRoot, specRel))
	out := filepath.Join(t.TempDir(), "testpack.json")
	require.NoError(t, pairtest.WriteRecord(out, pass))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var back pairtest.Record
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Equal(t, pass.Record, back)

	fail := run(t, editSpec(t, func(m map[string]any) { m["runtime"].([]any)[0].(map[string]any)["want_result"] = "PERMIT" }))
	out2 := filepath.Join(t.TempDir(), "never.json")
	require.Error(t, pairtest.WriteRecord(out2, fail))
	require.NoFileExists(t, out2)
}

func TestAFailedRecordWriteSaysWhichStepFailedAndLeavesNoTempFile(t *testing.T) {
	pass := run(t, filepath.Join(repoRoot, specRel))

	// The target is a directory, so the final rename fails after the temp file was written.
	dir := t.TempDir()
	target := filepath.Join(dir, "testpack.json")
	require.NoError(t, os.Mkdir(target, 0o750))
	err := pairtest.WriteRecord(target, pass)
	require.ErrorContains(t, err, "publish the record")
	require.NoFileExists(t, target+".tmp", "a failed write must not leave its temp file behind")

	// The parent is a file, so the directory cannot be created.
	file := filepath.Join(dir, "a-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	err = pairtest.WriteRecord(filepath.Join(file, "sub", "testpack.json"), pass)
	require.ErrorContains(t, err, "create the record directory")
}
