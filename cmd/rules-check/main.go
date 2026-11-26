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
	"os/signal"
	"syscall"

	"github.com/sspl/sspl-cip-rego-rules/internal/rulescheck"
)

func main() {
	root := flag.String("root", ".", "repository root (holds rulesets/ and contract/)")
	flag.Parse()

	// A cancelled CI job or Ctrl-C stops the checks between rulesets instead of killing the process mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	problems, err := rulescheck.Check(ctx, *root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules-check:", err)
		os.Exit(2)
	}
	// The control-plane family has its own manifest, registry and bundle (docs/rules-contract.md in the PDS, section 11).
	control, err := rulescheck.CheckControl(ctx, *root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules-check:", err)
		os.Exit(2)
	}
	problems = append(problems, control...)
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "rules-check: %d problem(s); these rules must not ship\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("rules-check: ok")
}
