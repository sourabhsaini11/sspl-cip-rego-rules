package conformance_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/conformance"
)

const policy = `package cip.pde.demo.v1

# a comment with <= and "PERMIT" must never be mutated
limit_ok if input.facts.amount <= input.values.limit

decision := {"result": "PERMIT", "reason": "OK"} if {
	limit_ok
	not input.facts.blocked
}

decision := {"result": "DENY", "reason": "TOO_MUCH"} if not limit_ok
`

const strongTests = `package cip.pde.demo.v1_test

import data.cip.pde.demo.v1 as demo

base := {"facts": {"amount": 5, "blocked": false}, "values": {"limit": 5}}

test_at_the_limit_is_permitted if {
	d := demo.decision with input as base
	d.result == "PERMIT"
}

test_over_the_limit_is_denied if {
	d := demo.decision with input as object.union(base, {"facts": {"amount": 6}})
	d.result == "DENY"
}

test_blocked_is_not_permitted if {
	not demo.decision with input as object.union(base, {"facts": {"blocked": true}})
}
`

// weakTests never test the boundary, so "<=" turned into "<" goes unnoticed.
const weakTests = `package cip.pde.demo.v1_test

import data.cip.pde.demo.v1 as demo

test_a_small_amount_is_permitted if {
	d := demo.decision with input as {"facts": {"amount": 1, "blocked": false}, "values": {"limit": 5}}
	d.result == "PERMIT"
}

test_a_big_amount_is_denied if {
	d := demo.decision with input as {"facts": {"amount": 9, "blocked": false}, "values": {"limit": 5}}
	d.result == "DENY"
}

test_blocked_is_not_permitted if {
	not demo.decision with input as {"facts": {"amount": 1, "blocked": true}, "values": {"limit": 5}}
}
`

func TestMutantsLeaveCommentsAndStringsAlone(t *testing.T) {
	for _, m := range conformance.Mutants(policy) {
		require.NotEqual(t, 3, m.Line, "a comment is never mutated")
		require.NotContains(t, m.Operator, "string:OK", "a reason is not a result")
	}
}

func TestMutantsCoverComparisonsResultsAndNegation(t *testing.T) {
	var ops []string
	for _, m := range conformance.Mutants(policy) {
		ops = append(ops, m.Operator)
	}
	require.Contains(t, ops, "<=→<")
	require.Contains(t, ops, "result:PERMIT→DENY")
	require.Contains(t, ops, "result:DENY→PERMIT")
	require.Contains(t, ops, "drop not")
}

func TestEveryMutantChangesExactlyOneThing(t *testing.T) {
	for _, m := range conformance.Mutants(policy) {
		require.NotEqual(t, policy, m.Source)
		require.Equal(t, len(m.Source)-len(policy), len(m.To)-len(m.From), "%s: one replacement, nothing else", m.Operator)
	}
}

func TestStrongTestsKillEveryMutant(t *testing.T) {
	res, err := conformance.Run(context.Background(), policy, strongTests)

	require.NoError(t, err)
	require.NotZero(t, res.Killed)
	require.Empty(t, res.Survivors, "%v", res.Survivors)
}

func TestWeakTestsLeaveASurvivorThatIsReported(t *testing.T) {
	res, err := conformance.Run(context.Background(), policy, weakTests)

	require.NoError(t, err)
	var ops []string
	for _, s := range res.Survivors {
		ops = append(ops, s.Operator)
	}
	require.Contains(t, ops, "<=→<", "the boundary is untested")
}

func TestAMutantThatDoesNotCompileIsNotCountedAgainstTheTests(t *testing.T) {
	res, err := conformance.Run(context.Background(), policy, strongTests)

	require.NoError(t, err)
	require.GreaterOrEqual(t, res.Total, res.Killed+len(res.Survivors)+res.Invalid)
}

func TestTheOriginalMustPassItsTestsFirst(t *testing.T) {
	_, err := conformance.Run(context.Background(), policy, `package cip.pde.demo.v1_test

test_fails if { false }
`)

	require.ErrorContains(t, err, "original")
}

// ---- the repository ----

func TestTheCheckedInRulesetsLeaveNoMutantUnnoticed(t *testing.T) {
	rep, err := conformance.MutateRepo(context.Background(), "../..")

	require.NoError(t, err)
	require.NotEmpty(t, rep.Rulesets)
	require.Truef(t, rep.OK(), "a rule the tests do not pin down, or a stale acceptance:\n%s", rep.Markdown())
}

func TestAReviewedEquivalentMutantIsAcceptedAndAStaleAcceptanceIsNot(t *testing.T) {
	root := scratchRoot(t, weakTests)

	rep, err := conformance.MutateRepo(context.Background(), root)
	require.NoError(t, err)
	require.False(t, rep.OK(), "the weak tests leave survivors")

	var accepted []map[string]string
	for _, s := range rep.Rulesets[0].Unaccepted {
		accepted = append(accepted, map[string]string{"ruleset": "BRIDGE-DEMO v1", "operator": s.Operator, "line_text": s.LineText, "reason": "reviewed"})
	}
	writeAccepted(t, root, accepted)
	rep, err = conformance.MutateRepo(context.Background(), root)
	require.NoError(t, err)
	require.True(t, rep.OK(), "every survivor was reviewed:\n%s", rep.Markdown())

	writeAccepted(t, root, append(accepted, map[string]string{"ruleset": "BRIDGE-DEMO v1", "operator": "<→<=", "line_text": "no such line", "reason": "old"}))
	rep, err = conformance.MutateRepo(context.Background(), root)
	require.NoError(t, err)
	require.False(t, rep.OK(), "an acceptance that matches nothing is stale and fails")
	require.Len(t, rep.Stale, 1)
}
