// Command rules-conformance runs the conformance checks of the rules repository (PDE architecture
// document, component 11):
//
//	rules-conformance mutate    mutate every ruleset and require its tests to notice
//	rules-conformance compat    compare adjacent versions of a profile on a corpus (N and N-1)
//
// Both exit non-zero when something unreviewed is found. Run `rules-check` first.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sspl/sspl-cip-rego-rules/internal/conformance"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rules-conformance mutate|compat [root]")
		os.Exit(2)
	}
	root := "."
	if len(os.Args) > 2 {
		root = os.Args[2]
	}
	ok, err := run(context.Background(), os.Args[1], root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules-conformance:", err)
		os.Exit(1)
	}
	if !ok {
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd, root string) (bool, error) {
	switch cmd {
	case "mutate":
		rep, err := conformance.MutateRepo(ctx, root)
		if err != nil {
			return false, err
		}
		fmt.Print(rep.Markdown())
		return rep.OK(), nil
	case "compat":
		rep, err := conformance.CompareRepo(ctx, root)
		if err != nil {
			return false, err
		}
		fmt.Print(rep.Markdown())
		return rep.OK(), nil
	default:
		return false, fmt.Errorf("unknown command %q", cmd)
	}
}
