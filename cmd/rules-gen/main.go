// Command rules-gen turns published profiles into bindings and assembles an unsigned bundle
// directory: the rulesets, the templates, the bindings and a manifest template that lists
// them. The signing step takes that directory as its source.
//
//	rules-gen -catalogue catalogue.json -profile profile.json [-profile ...] -out DIR
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
	flag.Var(&profiles, "profile", "published-profile file (JSON); repeatable")
	flag.Parse()

	rep, err := rulesgen.Generate(rulesgen.Options{Root: *root, Catalogue: *catalogue, Profiles: profiles, Out: *out})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, s := range rep.Skipped {
		fmt.Printf("skipped %s: %s\n", s.RuleID, s.Why)
	}
	fmt.Printf("rules-gen: %d rule(s) bound; unsigned bundle in %s\n", rep.Bound, *out)
}
