// Command rules-pairtest is the pair conformance gate: it tests a configuration and a policy together (the control rules judge the proposed
// configuration, the runtime ruleset decides under the configuration they approve, mutation and N/N-1 are clean) and, only when everything
// passes, writes a TESTPACK- record naming what was tested. `pds-release` requires that record (PDE architecture document component 11 and
// section 13).
//
//	rules-pairtest -spec conformance/pairs/bridge_upi_v7.json -out build/testpack.json [-root .]
//
// Exit codes: 0 passed (the record is written), 1 failed (nothing is written), 2 usage error or a run that could not be made.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sspl/sspl-cip-rego-rules/internal/pairtest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules-pairtest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository root (holds rulesets/, control/ and conformance/)")
	spec := fs.String("spec", "", "the pair's conformance spec (JSON)")
	out := fs.String("out", "", "where to write the TESTPACK- record on a pass")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *spec == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "rules-pairtest: needs -spec and -out")
		return 2
	}
	res, err := pairtest.Run(ctx, *root, *spec, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rules-pairtest: %v\n", err)
		return 2
	}
	if !res.Passed {
		for _, f := range res.Failures {
			_, _ = fmt.Fprintln(stderr, "FAIL: "+f)
		}
		_, _ = fmt.Fprintf(stderr, "rules-pairtest: %d failure(s); no testpack is written\n", len(res.Failures))
		return 1
	}
	if err := pairtest.WriteRecord(*out, res); err != nil {
		_, _ = fmt.Fprintf(stderr, "rules-pairtest: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "%s: %d configuration case(s), %d runtime case(s), %d/%d mutants killed; record in %s\n",
		res.Record.ID, res.Record.Results.ConfigurationCases, res.Record.Results.RuntimeCases, res.Record.Results.Mutants.Killed, res.Record.Results.Mutants.Total, *out)
	return 0
}
