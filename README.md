# sspl-cip-rego-rules

The Rego rules the CIP **Policy Decision Service** (PDS) evaluates, with the gate that decides whether
they may ship. Confidential: SSPL internal, company GitLab only.

A rule answers one question for one profile: given this request's facts, this bank's signed limits and
today's usage, is the operation allowed, and why. The PDS embeds OPA and never looks inside a rule; it
records whatever comes back. This repository is where that logic is written, reviewed and tested.

## How it fits

```
sspl-cip-rego-rules  --make check-->  signed bundle  --Bundle Manager-->  PDS (sspl-cip-policy-decision-service)
   (Git, reviewed)                    (pipeline, KMI)                        verify, compile, swap, evaluate
```

The two services are kept in step by one document, owned by the PDS:
**`../sspl-cip-policy-decision-service/docs/rules-contract.md`**. It defines the rule input, the
`decision` output, the manifest, the fact-schema format and the reason registry. Read it before
changing a rule's shape. `contract/README.md` here says which version these rules are written for.

## Layout

```
rulesets/
  manifest.template.json          the profiles and versions that ship (the pipeline stamps revision, git_commit, mac)
  <profile_snake>/<version>/
    policy.rego                   package cip.pde.<profile_snake>.<version>, exposes `decision`
    fact-schema.json              the closed set of request facts the ruleset accepts
    policy_test.rego              the rule's own tests
contract/
  reasons.json                    every reason a rule may return, per profile
  README.md                       the contract version these rules target
cmd/rules-check/                  the gate, as a command
internal/rulescheck/              the gate's checks and their tests
```

Shipping now: `BRIDGE-UPI v5`, `BRIDGE-AEPS v2`, `BRIDGE-BALANCE-INQUIRY v1`. They began as a copy of the
PDS's reference rulesets (PDS commit `c2e12d1`, 2026-11-03) and now evolve here.

## Commands

```bash
make check    # the gate: exit 0 only if these rules may be signed and shipped
make test     # the gate's own tests: every kind of defect must be caught, and the real rules must pass
make lint     # golangci-lint
```

`make check` verifies: every ruleset is in the manifest and complete; package, profile and version follow
the contract; no number other than 0, 1, 6, 22 in a rule (limits live in signed bank state, not in Git);
every reason a rule returns is registered, and no registered reason is unused; no rule returns a reason the
PDS keeps for itself; every `reason_code` is one of the four `CIP-POL-*` codes; every Rego test passes.

## Adding or changing a rule

1. Write `policy.rego`, `fact-schema.json` and `policy_test.rego` under `rulesets/<profile_snake>/<version>/`.
   A new behaviour is a new version; do not edit a shipped version in place.
2. List it in `rulesets/manifest.template.json`; register its reasons in `contract/reasons.json`.
3. `make test && make check`.
4. Open a merge request. Nothing here changes the PDS.

The rules are written so that a **missing or mistyped value leaves `decision` undefined**: the PDS records
that as a REJECT (`RULE_UNDEFINED`). Absence never means allow. In Rego a number sorts before a string, so
guard every limit with `is_number(x)` and `x == round(x)`.

## Versions

OPA is pinned to **v1.17.1** (core-runtime's version, the same as the PDS) and Go to 1.26. Add a dependency
with an explicit `@version`, never `go get -u`, and confirm `go.mod` still says OPA v1.17.1 afterwards. The
gate compiles with the same OPA as the PDS, so a rule that passes here compiles there.

## Not decided yet

Owners and details are in the PDS's `docs/bundle-publishing.md`: the KMI bundle key, the canonical bytes the
MAC covers (DEP-05), where revision numbers come from, how the signed bundle reaches every PDS instance, and
which tool signs in the pipeline. This repository's GitLab pipeline is to be added by cloud devops.

## Templates and bindings (the second rule source)

Besides the hand-written rulesets (P0), the bundle can carry reviewed **templates** (P1), one per catalogue
rule type, in `templates/<rule_type>/` (`rule.rego`, `rule_test.rego`, `template.json`). A template holds no
limit: it reads the number from `input.values[input.rule.value_key]`. On a profile publish, `cmd/rules-gen`
writes **bindings** (which template applies to which operation, and the key to read) and assembles an
unsigned bundle directory for the signing step. The PDS combines both sources with deny wins. Design and
decisions: `../sspl-cip-policy-decision-service/docs/rego-rule-sources.md`.

```bash
go run ./cmd/rules-gen -catalogue catalogue.json -profile profile.json -out /path/to/unsigned
```

Bindings are written for **every** version of the profile's ruleset in the manifest (a bank pinned to an older
version still gets its configured limits), or for the versions a profile names in an optional `"versions": [...]`.
A version that cannot host a configured rule (the template reads a fact its schema lacks) fails the generation
rather than leaving the rule silently off.

## Policy proposals (Git feeds the Policy Governance Service)

The Landing Zone's Policy Governance Service owns policy approval (PDE architecture document, section 7.1.1);
this repository is the source it takes reviewed Rego from. One proposal file per ruleset version:

```bash
go run ./cmd/rules-gen -proposals /path/to/proposals -git-commit "$(git rev-parse HEAD)"
```

Each file carries the ruleset (profile, version, package, entry point), the input contract, a digest of what
ships in the bundle (never the tests), the commit, and an empty `review.evidence` the pipeline must fill from the
merge request: the repository cannot know who approved it. Provisional design, to be verified with the Landing
Zone owners: `../sspl-cip-policy-decision-service/docs/policy-binding.md`.

`make check` also covers the templates and the template reasons in `contract/reasons.json`
(`template_reasons`, registered per rule type).
