# CLAUDE.md

Guidance for Claude Code working in this repository. CIP content is confidential: keep everything inside the
company GitLab (gitlab.sahakarsarathi.co.in); no Artifact/Docs publishing, web search/fetch or uploads with CIP
content. Ask first if unsure.

## What this is

The Rego rules the CIP Policy Decision Service evaluates, plus the gate (`rules-check`) that decides whether they
may be signed and shipped. Start with `README.md`, then the contract:
`../sspl-cip-policy-decision-service/docs/rules-contract.md` (owned by the PDS; do not copy it here).

## Commands

```bash
make check    # the gate
make test     # go test -race ./... (each kind of defect must be caught; the real rules must pass)
make lint     # golangci-lint (gofumpt)
make fuzz     # 20 s per parser target (the seeds also run in make test)
```

## Rules of the road

1. **Rules carry no data.** Limits and thresholds arrive in `input.values` / `input.live`. Only 0, 1, 6, 22 may appear as numbers.
2. **Fail closed.** A missing or mistyped value leaves `decision` undefined (the PDS records REJECT `RULE_UNDEFINED`). Guard limits with `is_number(x)` and `x == round(x)`: a number sorts before a string in Rego.
3. **Every reason is registered** in `contract/reasons.json` for its profile. Never return `POLICY_REF_MISMATCH` or `RULE_UNDEFINED`: they are the PDS's.
4. **A new behaviour is a new version.** Do not edit a shipped ruleset version in place.
5. **The gate must be able to fail.** Any new check comes with a test that breaks a copy of the repo and expects the check to notice (`internal/rulescheck/rulescheck_test.go`).
6. **A ruleset's tests must kill every mutant** (`make mutate`) and a newer version may not loosen a decision on the corpus (`make compat`, `conformance/compat/<profile>.json`). Run `make promote-check` before a change is ready.
7. **Contract changes start in the PDS.** If a rule needs a different input, manifest field or output, change `docs/rules-contract.md` in the PDS first; this repository follows.

## Conventions

- **Dependencies:** OPA is pinned to **v1.17.1** (core-runtime's version, same as the PDS). Go 1.26 (`go 1.26.0`, `toolchain go1.26.11`). Add a dependency with an explicit `@version`; never `go get -u`; confirm OPA is still v1.17.1 and `go` still 1.26.0 afterwards.
- Rego v1 syntax, compiled strictly. `in` is a reserved word; `with` cannot sit inside parentheses; `object.union` merges recursively.
- `gofumpt` + `goimports -local github.com/sspl/sspl-cip-rego-rules`, `.golangci.yml` as in the PDS.
- Conventional commits (`feat:`, `fix:`, `test:`, `chore:`). No AI attribution trailers in commits. Commit and push only when asked; never force-push; never `--no-verify`.
- Identity comes from the remote URL (machine-wide git-workflow skill). The remote is configured but the GitLab project may not exist yet: do not create it or push without being asked.
