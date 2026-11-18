package conformance_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/conformance"
)

// A profile with two versions: v1 permits up to the limit, v2 is configured by the test.
func compatRoot(t *testing.T, v2Body string) string {
	t.Helper()
	root := t.TempDir()
	put := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
	put("rulesets/manifest.template.json", `{"rulesets":[
 {"profile":"BRIDGE-DEMO","version":"v1","package":"cip.pde.demo.v1","path":"demo/v1"},
 {"profile":"BRIDGE-DEMO","version":"v2","package":"cip.pde.demo.v2","path":"demo/v2"}]}`)
	put("rulesets/demo/v1/policy.rego", `package cip.pde.demo.v1

decision := {"result": "PERMIT", "reason": "OK"} if input.facts.amount <= input.values.limit

decision := {"result": "DENY", "reason": "OVER"} if input.facts.amount > input.values.limit
`)
	put("rulesets/demo/v2/policy.rego", "package cip.pde.demo.v2\n\n"+v2Body)
	return root
}

const corpus = `{"profile":"BRIDGE-DEMO","operation":"PAY","cases":[
 {"name":"under","facts":{"amount":3},"values":{"limit":5}},
 {"name":"at the limit","facts":{"amount":5},"values":{"limit":5}},
 {"name":"over","facts":{"amount":9},"values":{"limit":5}}]%s}`

func putCorpus(t *testing.T, root, allowed string) {
	t.Helper()
	extra := ""
	if allowed != "" {
		extra = `,"allowed_widening":` + allowed
	}
	p := filepath.Join(root, "conformance", "compat", "bridge_demo.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf(corpus, extra)), 0o600))
}

const sameAsV1 = `decision := {"result": "PERMIT", "reason": "OK"} if input.facts.amount <= input.values.limit

decision := {"result": "DENY", "reason": "OVER"} if input.facts.amount > input.values.limit
`

const narrower = `decision := {"result": "PERMIT", "reason": "OK"} if input.facts.amount < input.values.limit

decision := {"result": "DENY", "reason": "OVER"} if input.facts.amount >= input.values.limit
`

const wider = `decision := {"result": "PERMIT", "reason": "OK"} if input.facts.amount <= 99
`

func TestAnUnchangedVersionIsCompatible(t *testing.T) {
	root := compatRoot(t, sameAsV1)
	putCorpus(t, root, "")

	rep, err := conformance.CompareRepo(context.Background(), root)

	require.NoError(t, err)
	require.True(t, rep.OK(), rep.Markdown())
	require.Equal(t, 3, rep.Pairs[0].Same)
}

func TestANarrowerVersionIsReportedAndAllowed(t *testing.T) {
	root := compatRoot(t, narrower)
	putCorpus(t, root, "")

	rep, err := conformance.CompareRepo(context.Background(), root)

	require.NoError(t, err)
	require.True(t, rep.OK(), "narrowing never loosens a decision: %s", rep.Markdown())
	require.Equal(t, 1, rep.Pairs[0].Narrowed)
	require.Contains(t, rep.Markdown(), "at the limit")
}

func TestAWiderVersionFailsUnlessEachWideningIsReviewed(t *testing.T) {
	root := compatRoot(t, wider)
	putCorpus(t, root, "")

	rep, err := conformance.CompareRepo(context.Background(), root)
	require.NoError(t, err)
	require.False(t, rep.OK())
	require.Equal(t, "over", rep.Pairs[0].Unreviewed[0].Case)

	putCorpus(t, root, `[{"from":"v1","to":"v2","case":"over","reason":"v2 raises the cap on purpose"}]`)
	rep, err = conformance.CompareRepo(context.Background(), root)
	require.NoError(t, err)
	require.True(t, rep.OK(), rep.Markdown())
}

func TestAReviewedWideningThatNoLongerHappensIsStale(t *testing.T) {
	root := compatRoot(t, sameAsV1)
	putCorpus(t, root, `[{"from":"v1","to":"v2","case":"over","reason":"old"}]`)

	rep, err := conformance.CompareRepo(context.Background(), root)

	require.NoError(t, err)
	require.False(t, rep.OK())
	require.Len(t, rep.Stale, 1)
}

func TestAProfileWithTwoVersionsAndNoCorpusFails(t *testing.T) {
	root := compatRoot(t, sameAsV1)

	_, err := conformance.CompareRepo(context.Background(), root)

	require.ErrorContains(t, err, "BRIDGE-DEMO")
	require.ErrorContains(t, err, "corpus")
}

func TestTheCheckedInVersionsNeverWidenWithoutReview(t *testing.T) {
	rep, err := conformance.CompareRepo(context.Background(), "../..")

	require.NoError(t, err)
	require.NotEmpty(t, rep.Pairs, "BRIDGE-UPI and BRIDGE-AEPS each have two versions")
	require.Truef(t, rep.OK(), "%s", rep.Markdown())
}

// A version that narrows only under a posture is invisible to a corpus that always runs NORMAL.
const narrowerWhenGuarded = `decision := {"result": "PERMIT", "reason": "OK"} if {
	input.posture.operating == "GUARDED"
	input.facts.amount < input.values.limit
}

decision := {"result": "DENY", "reason": "OVER"} if {
	input.posture.operating == "GUARDED"
	input.facts.amount >= input.values.limit
}

decision := {"result": "PERMIT", "reason": "OK"} if {
	input.posture.operating != "GUARDED"
	input.facts.amount <= input.values.limit
}

decision := {"result": "DENY", "reason": "OVER"} if {
	input.posture.operating != "GUARDED"
	input.facts.amount > input.values.limit
}
`

func TestACaseCanRunUnderAPostureAndSeeWhatOnlyThatPostureChanges(t *testing.T) {
	root := compatRoot(t, narrowerWhenGuarded)
	p := filepath.Join(root, "conformance", "compat", "bridge_demo.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(`{"profile":"BRIDGE-DEMO","operation":"PAY","cases":[
 {"name":"at the limit, normal","facts":{"amount":5},"values":{"limit":5}},
 {"name":"at the limit, guarded","posture":"GUARDED","facts":{"amount":5},"values":{"limit":5}}]}`), 0o600))

	rep, err := conformance.CompareRepo(context.Background(), root)

	require.NoError(t, err)
	require.True(t, rep.OK(), rep.Markdown())
	require.Equal(t, 1, rep.Pairs[0].Same, "normal posture: unchanged")
	require.Equal(t, 1, rep.Pairs[0].Narrowed, "guarded posture: the newer version is stricter")
	require.Contains(t, rep.Markdown(), "at the limit, guarded")
}
