// Command rules-gen turns published profiles into bindings and assembles an unsigned bundle
// directory: the rulesets, the templates, the bindings and a manifest template that lists
// them. The signing step takes that directory as its source.
//
//	rules-gen -catalogue catalogue.json -profile profile.json [-profile ...] -out DIR [-policy-data DIR]
//	rules-gen -proposals DIR -git-commit SHA
//
// The second form writes one policy proposal per ruleset version, for the Landing Zone's Policy
// Governance Service (docs/policy-binding.md in the PDS repository). The two forms may be combined.
//
// Run `rules-check` first: this command trusts that the rules and templates passed the gate.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulesgen"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var profiles list
	root := flag.String("root", ".", "repository root (holds rulesets/ and templates/)")
	catalogue := flag.String("catalogue", "", "catalogue export (JSON)")
	out := flag.String("out", "", "directory to create for the unsigned bundle")
	policyData := flag.String("policy-data", "", "directory to create for the bindings as a separate policy-data artefact; the bundle then carries none (PDE architecture document, section 13)")
	flag.Var(&profiles, "profile", "published-profile file (JSON); repeatable")
	proposals := flag.String("proposals", "", "directory to create for the policy proposals (one file per ruleset version)")
	gitCommit := flag.String("git-commit", "", "the 40-hex commit the proposals describe")
	flag.Parse()

	if *proposals != "" {
		if err := rulesgen.WriteProposals(rulesgen.ProposalOptions{Root: *root, GitCommit: *gitCommit}, *proposals); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("rules-gen: policy proposals in %s\n", *proposals)
		if *out == "" {
			return
		}
	}

	rep, err := rulesgen.Generate(rulesgen.Options{Root: *root, Catalogue: *catalogue, Profiles: profiles, Out: *out, PolicyDataOut: *policyData})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, s := range rep.Skipped {
		fmt.Printf("skipped %s: %s\n", s.RuleID, s.Why)
	}
	fmt.Printf("rules-gen: %d rule(s) bound; unsigned bundle in %s\n", rep.Bound, *out)
	if *policyData != "" {
		fmt.Printf("rules-gen: policy data (the bindings) in %s: sign and release it separately from the bundle\n", *policyData)
	}
}
