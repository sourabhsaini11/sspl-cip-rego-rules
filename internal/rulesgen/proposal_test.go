package rulesgen_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulesgen"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

func proposals(t *testing.T, root, gitCommit string) ([]rulesgen.Proposal, error) {
	t.Helper()
	return rulesgen.Proposals(rulesgen.ProposalOptions{Root: root, GitCommit: gitCommit})
}

func TestEveryRulesetVersionIsOneProposal(t *testing.T) {
	root := miniRoot(t, factsWithAmount)

	got, err := proposals(t, root, commit)

	require.NoError(t, err)
	require.Len(t, got, 2)
	p := got[1]
	require.Equal(t, "pde-policy-proposal/v1", p.Format)
	require.Equal(t, rulesgen.ProposalRuleset{
		Profile: "BRIDGE-UPI", Version: "v5", Package: "cip.pde.bridge_upi.v5", Entrypoint: "cip/pde/bridge_upi/v5/decision",
	}, p.Ruleset)
	require.Equal(t, "v1", p.InputContract)
	require.Equal(t, commit, p.GitCommit)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, p.ContentDigest)
	require.True(t, p.Review.Required)
	require.Nil(t, p.Review.Evidence, "the repository cannot know who approved the merge request")
}

func TestTheDigestFollowsTheRulesNotTheClock(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	a, err := proposals(t, root, commit)
	require.NoError(t, err)
	b, err := proposals(t, root, commit)
	require.NoError(t, err)
	require.Equal(t, a, b, "deterministic")

	require.NoError(t, os.WriteFile(filepath.Join(root, "rulesets/bridge_upi/v5/policy.rego"), []byte("package cip.pde.bridge_upi.v5\n# changed\n"), 0o600))
	c, err := proposals(t, root, commit)
	require.NoError(t, err)
	require.NotEqual(t, a[1].ContentDigest, c[1].ContentDigest, "a changed rule is a different policy")
	require.Equal(t, a[0].ContentDigest, c[0].ContentDigest, "an untouched version keeps its digest")
}

func TestATestFileDoesNotChangeTheDigest(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	a, err := proposals(t, root, commit)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(root, "rulesets/bridge_upi/v5/policy_test.rego"), []byte("package x\n"), 0o600))
	b, err := proposals(t, root, commit)
	require.NoError(t, err)

	require.Equal(t, a, b, "tests are for reviewers, not the bundle")
}

func TestAProposalNeedsAGitCommit(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	for _, c := range []string{"", "HEAD", "0123", "0123456789ABCDEF0123456789abcdef01234567"} {
		_, err := proposals(t, root, c)
		require.Error(t, err, "%q", c)
	}
}

func TestWriteProposalsWritesOneFilePerVersionAndRefusesANonEmptyDirectory(t *testing.T) {
	root := miniRoot(t, factsWithAmount)
	out := filepath.Join(t.TempDir(), "proposals")

	require.NoError(t, rulesgen.WriteProposals(rulesgen.ProposalOptions{Root: root, GitCommit: commit}, out))

	raw, err := os.ReadFile(filepath.Join(out, "BRIDGE-UPI-v5.proposal.json"))
	require.NoError(t, err)
	var p rulesgen.Proposal
	require.NoError(t, json.Unmarshal(raw, &p))
	require.Equal(t, "v5", p.Ruleset.Version)
	require.FileExists(t, filepath.Join(out, "BRIDGE-UPI-v4.proposal.json"))
	require.Error(t, rulesgen.WriteProposals(rulesgen.ProposalOptions{Root: root, GitCommit: commit}, out), "never overwrite a previous run")
}
