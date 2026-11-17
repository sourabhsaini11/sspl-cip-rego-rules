// Package conformance is the part of the Policy Conformance Service (PDE architecture document,
// component 11 and section 33) that the rules repository can own: mutation testing of every ruleset
// against its own Rego tests, and an N / N-1 comparison of adjacent ruleset versions. Both turn
// "the tests pass" into evidence that the tests would notice a wrong rule.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
)

// Mutant is the policy with one small change.
type Mutant struct {
	Ruleset  string // set by the caller
	Line     int    // 1-based
	Operator string // for example "<=→<" or "result:PERMIT→DENY"
	From, To string
	LineText string // the original line, trimmed
	Source   string // the mutated policy
}

// resultMutations turn a restrictive result into a permit and a permit into a deny. A rule whose
// STEP_UP or REFER answer is wrongly widened to PERMIT is the mistake that matters most.
var resultMutations = map[string]string{
	"PERMIT": "DENY", "DENY": "PERMIT", "STEP_UP": "PERMIT", "REFER": "PERMIT", "NEED_EVIDENCE": "PERMIT",
}

// Mutants returns every single-change mutant of a Rego policy: comparison operators, binary
// plus and minus, the seven-result strings, boolean literals and a dropped `not`. Comments and
// other strings are never touched, and each mutant changes exactly one thing.
func Mutants(src string) []Mutant {
	var out []Mutant
	line, lineStart := 1, 0
	i := 0
	add := func(pos, n int, operator, to string) {
		text := strings.TrimSpace(src[lineStart:endOfLine(src, lineStart)])
		out = append(out, Mutant{
			Line: line, Operator: operator, From: src[pos : pos+n], To: to, LineText: text,
			Source: src[:pos] + to + src[pos+n:],
		})
	}
	for i < len(src) {
		c := src[i]
		switch c {
		case '\n':
			line++
			lineStart = i + 1
			i++
		case '#': // a comment runs to the end of the line
			i = endOfLine(src, i)
		case '`': // a raw string
			j := strings.IndexByte(src[i+1:], '`')
			if j < 0 {
				return out
			}
			line += strings.Count(src[i:i+1+j+1], "\n")
			i += j + 2
		case '"':
			j := i + 1
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return out
			}
			if to, ok := resultMutations[src[i+1:j]]; ok {
				add(i+1, j-i-1, "result:"+src[i+1:j]+"→"+to, to)
			}
			i = j + 1
		default:
			if n, op, to := operatorAt(src, i); n > 0 {
				add(i, n, op, to)
				i += n
				continue
			}
			if word, ok := wordAt(src, i); ok {
				switch word {
				case "true":
					add(i, 4, "bool:true→false", "false")
				case "false":
					add(i, 5, "bool:false→true", "true")
				case "not":
					if standsAlone(src, i, 3) && i+4 < len(src) && src[i+3] == ' ' {
						add(i, 4, "drop not", "")
					}
				}
				i += len(word)
				continue
			}
			i++
		}
	}
	return out
}

func endOfLine(src string, from int) int {
	if j := strings.IndexByte(src[from:], '\n'); j >= 0 {
		return from + j
	}
	return len(src)
}

// operatorAt recognises a comparison or a spaced plus or minus at i.
func operatorAt(src string, i int) (n int, name, to string) {
	two := func(op, repl string) (int, string, string) { return 2, op + "→" + repl, repl }
	switch {
	case strings.HasPrefix(src[i:], "<="):
		return two("<=", "<")
	case strings.HasPrefix(src[i:], ">="):
		return two(">=", ">")
	case strings.HasPrefix(src[i:], "=="):
		return two("==", "!=")
	case strings.HasPrefix(src[i:], "!="):
		return two("!=", "==")
	case src[i] == '<' && !strings.HasPrefix(src[i:], "<-"):
		return 1, "<→<=", "<="
	case src[i] == '>':
		return 1, ">→>=", ">="
	case (src[i] == '+' || src[i] == '-') && i > 0 && src[i-1] == ' ' && i+1 < len(src) && src[i+1] == ' ':
		if src[i] == '+' {
			return 1, "+→-", "-"
		}
		return 1, "-→+", "+"
	}
	return 0, "", ""
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func wordAt(src string, i int) (string, bool) {
	if !isWordByte(src[i]) || (i > 0 && (isWordByte(src[i-1]) || src[i-1] == '.')) {
		return "", false
	}
	j := i
	for j < len(src) && isWordByte(src[j]) {
		j++
	}
	return src[i:j], true
}

// standsAlone reports whether the n bytes at i are a whole word.
func standsAlone(src string, i, n int) bool {
	return (i == 0 || !isWordByte(src[i-1])) && (i+n >= len(src) || !isWordByte(src[i+n]))
}

// Result is the outcome of running every mutant of one policy against its tests.
type Result struct {
	Total     int      // mutants generated
	Killed    int      // the tests failed on them
	Invalid   int      // the mutant did not compile: nothing to say about the tests
	Survivors []Mutant // the tests still passed: a rule they do not pin down
}

// Run mutates the policy, one change at a time, and runs the tests against each mutant. The
// original must pass its tests first.
func Run(ctx context.Context, policy, tests string) (Result, error) {
	ok, err := passes(ctx, policy, tests)
	if err != nil {
		return Result{}, fmt.Errorf("conformance: the original policy: %w", err)
	}
	if !ok {
		return Result{}, errors.New("conformance: the original policy does not pass its own tests")
	}
	var res Result
	for _, m := range Mutants(policy) {
		res.Total++
		passed, err := passes(ctx, m.Source, tests)
		switch {
		case err != nil:
			res.Invalid++
		case passed:
			res.Survivors = append(res.Survivors, m)
		default:
			res.Killed++
		}
	}
	return res, nil
}

// passes compiles the policy and its tests strictly and runs them. An error means the pair did not
// compile or could not run.
func passes(ctx context.Context, policy, tests string) (bool, error) {
	mods := map[string]*ast.Module{}
	for name, src := range map[string]string{"policy.rego": policy, "policy_test.rego": tests} {
		mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return false, err
		}
		mods[name] = mod
	}
	compiler := ast.NewCompiler().WithStrict(true)
	if compiler.Compile(mods); compiler.Failed() {
		return false, compiler.Errors
	}
	ch, err := tester.NewRunner().SetCompiler(compiler).SetStore(inmem.New()).SetModules(mods).RunTests(ctx, nil)
	if err != nil {
		return false, err
	}
	ran := 0
	for r := range ch {
		ran++
		if r.Error != nil || r.Fail {
			return false, nil
		}
	}
	return ran > 0, nil
}
