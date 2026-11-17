// Command rules-check is the bundle pipeline's gate. It exits 0 only when every ruleset
// under the repository root may be signed and shipped; it exits 1 and prints each problem
// otherwise.
//
//	rules-check            # check the repository in the current directory
//	rules-check -root DIR
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulescheck"
)

func main() {
	root := flag.String("root", ".", "repository root (holds rulesets/ and contract/)")
	flag.Parse()

	problems, err := rulescheck.Check(context.Background(), *root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules-check:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "rules-check: %d problem(s); these rules must not ship\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("rules-check: ok")
}
