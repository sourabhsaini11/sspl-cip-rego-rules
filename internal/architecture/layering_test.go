// Package architecture holds the import rules of this repository as tests, so `make test` fails
// when one gate package starts depending on another by accident (SSPL-NFR GO-06, GO-08 and the
// import checks of section 6.2). It contains no production code.
package architecture

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/sspl/sspl-cip-rego-rules"

// graph maps a package import path to the import paths it names directly.
type graph map[string][]string

// allowed lists, for every package of this module, the other packages of this module it may
// import. A package that is not listed may import none. A new edge needs a line here and a reason:
// the packages are separate gates and tools, not layers of one program.
var allowed = map[string][]string{
	module + "/cmd/rules-check":       {module + "/internal/rulescheck"},
	module + "/cmd/rules-conformance": {module + "/internal/conformance"},
	module + "/cmd/rules-gen":         {module + "/internal/rulesgen"},
	module + "/cmd/rules-pairtest":    {module + "/internal/pairtest"},
	// The pair gate reuses the conformance runner to evaluate rules; nothing else crosses.
	module + "/internal/pairtest": {module + "/internal/conformance"},
}

func isModule(path string) bool { return path == module || strings.HasPrefix(path, module+"/") }

// violations returns one line per import of a module package that the table does not allow.
func violations(g graph) []string {
	var out []string
	for pkg, imports := range g {
		ok := map[string]bool{}
		for _, a := range allowed[pkg] {
			ok[a] = true
		}
		for _, imp := range imports {
			if isModule(imp) && !ok[imp] {
				out = append(out, pkg+" imports "+imp)
			}
		}
	}
	sort.Strings(out)
	return out
}

func loadGraph(t *testing.T) graph {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-json=ImportPath,Imports", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	g := graph{}
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		g[p.ImportPath] = p.Imports
	}
	if len(g) == 0 {
		t.Fatal("go list returned no packages")
	}
	return g
}

func TestThePackagesImportOnlyWhatTheTableAllows(t *testing.T) {
	if v := violations(loadGraph(t)); len(v) > 0 {
		t.Fatalf("import rule violations:\n%s", strings.Join(v, "\n"))
	}
}

// The table must not list a package that no longer exists, or a stale line would hide a new edge.
func TestTheTableNamesOnlyExistingPackages(t *testing.T) {
	g := loadGraph(t)
	for pkg, deps := range allowed {
		if _, ok := g[pkg]; !ok {
			t.Errorf("%s is in the allowed table but is not a package", pkg)
		}
		for _, d := range deps {
			if _, ok := g[d]; !ok {
				t.Errorf("%s allows %s, which is not a package", pkg, d)
			}
		}
	}
}

// The rules only count if they can fail: each case breaks one rule on a made-up graph.
func TestTheRulesCatchEachKindOfBreach(t *testing.T) {
	p := func(s string) string { return module + "/" + s }
	cases := []struct {
		name string
		g    graph
	}{
		{"a gate imports another gate", graph{p("internal/rulescheck"): {p("internal/rulesgen")}}},
		{"conformance imports pairtest", graph{p("internal/conformance"): {p("internal/pairtest")}}},
		{"a command imports another command's package", graph{p("cmd/rules-check"): {p("internal/pairtest")}}},
		{"an internal package imports a command", graph{p("internal/rulesgen"): {p("cmd/rules-gen")}}},
	}
	for _, c := range cases {
		if len(violations(c.g)) == 0 {
			t.Errorf("%s: the rules did not notice", c.name)
		}
	}
	legal := graph{
		p("cmd/rules-pairtest"):  {p("internal/pairtest"), "fmt"},
		p("internal/pairtest"):   {p("internal/conformance"), "github.com/open-policy-agent/opa/v1/rego"},
		p("internal/rulescheck"): {"os"},
	}
	if v := violations(legal); len(v) > 0 {
		t.Errorf("a legal graph was flagged:\n%s", strings.Join(v, "\n"))
	}
}
