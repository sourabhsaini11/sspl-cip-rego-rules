package rulesgen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

// A policy proposal is how a reviewed ruleset version reaches the Landing Zone's Policy Governance
// Service (docs/policy-binding.md in the PDS repository, B-8): Git feeds the service, it does not
// replace it. One file per ruleset version. The repository cannot know who approved the merge
// request, so the review evidence is empty until the pipeline fills it, and the service must not
// accept a proposal without it.

const proposalFormat = "pde-policy-proposal/v1"

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ProposalOptions names the inputs of one run.
type ProposalOptions struct {
	Root      string // the repository root
	GitCommit string // the 40-hex commit the proposals describe
}

// ProposalRuleset identifies the ruleset a proposal is for.
type ProposalRuleset struct {
	Profile    string `json:"profile"`
	Version    string `json:"version"`
	Package    string `json:"package"`
	Entrypoint string `json:"entrypoint"`
}

// ProposalReview says whether review is required and carries its evidence once the pipeline has it.
type ProposalReview struct {
	Required bool `json:"required"`
	Evidence any  `json:"evidence"`
}

// Proposal is one ruleset version offered to the Policy Governance Service.
type Proposal struct {
	Format        string          `json:"format"`
	Ruleset       ProposalRuleset `json:"ruleset"`
	InputContract string          `json:"input_contract"`
	ContentDigest string          `json:"content_digest"`
	GitCommit     string          `json:"git_commit"`
	Review        ProposalReview  `json:"review"`
}

// Proposals returns one proposal per ruleset version in the manifest, ordered by profile and version.
func Proposals(o ProposalOptions) ([]Proposal, error) {
	if !commitRe.MatchString(o.GitCommit) {
		return nil, errors.New("rulesgen: a proposal needs the 40-hex git commit it describes")
	}
	m, err := readManifest(o.Root)
	if err != nil {
		return nil, err
	}
	rs := append([]rulesetEntry(nil), m.Rulesets...)
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Profile != rs[j].Profile {
			return rs[i].Profile < rs[j].Profile
		}
		return versionNumber(rs[i].Version) < versionNumber(rs[j].Version)
	})
	out := make([]Proposal, 0, len(rs))
	for _, r := range rs {
		digest, err := rulesetDigest(o.Root, r)
		if err != nil {
			return nil, err
		}
		out = append(out, Proposal{
			Format: proposalFormat,
			Ruleset: ProposalRuleset{
				Profile: r.Profile, Version: r.Version, Package: r.Package,
				Entrypoint: strings.ReplaceAll(r.Package, ".", "/") + "/decision",
			},
			InputContract: m.InputContract,
			ContentDigest: digest,
			GitCommit:     o.GitCommit,
			Review:        ProposalReview{Required: true},
		})
	}
	return out, nil
}

// rulesetDigest is the sha256 over what goes into a bundle for the ruleset, never its tests: each
// shipped file as "name NUL sha256(file)", in name order.
func rulesetDigest(root string, r rulesetEntry) (string, error) {
	h := sha256.New()
	dir, err := safefs.Join(filepath.Join(root, "rulesets"), r.Path)
	if err != nil {
		return "", fmt.Errorf("rulesgen: %w", err)
	}
	for _, name := range []string{"fact-schema.json", "policy.rego"} { // name order
		b, err := safefs.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("rulesgen: %w", err)
		}
		sum := sha256.Sum256(b)
		_, _ = fmt.Fprintf(h, "%s\x00%s\n", name, hex.EncodeToString(sum[:])) // a hash never fails to write
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// WriteProposals writes one file per ruleset version into out, which must not exist or be empty.
func WriteProposals(o ProposalOptions, out string) error {
	if err := checkOut(out); err != nil {
		return err
	}
	ps, err := Proposals(o)
	if err != nil {
		return err
	}
	files := make(map[string][]byte, len(ps))
	for _, p := range ps {
		b, err := marshal(p)
		if err != nil {
			return err
		}
		files[p.Ruleset.Profile+"-"+p.Ruleset.Version+".proposal.json"] = b
	}
	return writeAll(out, files)
}
