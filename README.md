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

## The worked journeys (PDE architecture document, Part Four)

One ruleset per journey, written as a new version or a new profile (a shipped version is never edited). The values are
the document's dummy examples in the tests, not SSPL-approved limits. **Profile codes, operation codes, fact names and
value keys below are provisional: they are our proposal, to be verified with the Resolution Engine and the Definition
Catalogue owners** (the bank's values arrive in the signed state under these keys).

| Journey | Ruleset | Operations | Results it can give | Values the bank's state must publish |
|---|---|---|---|---|
| 1 UPI step-up (UPI-R19) | `BRIDGE-UPI v6` | `UPI_PAY` | PERMIT, STEP_UP (`UPI_DEVICE_RISK`, obligation `OTP_OR_APPROVED_FACTOR`), DENY | `per_txn_limit_inr`, `daily_limit_inr`, `night_cap_inr`, `step_up_threshold_inr` |
| 1b UPI under a GUARDED posture (section 3 scenario) | `BRIDGE-UPI v7` | `UPI_PAY` | v6 results (a verified completion of `OTP_OR_APPROVED_FACTOR` satisfies the step-up), plus DENY (`UPI_GUARDED_LIMIT_EXCEEDED`, `details.effective_limit_inr`) above the posture cap | the v6 keys; the GUARDED cap arrives with the posture (`input.posture.limit_inr`), not from the bank state. A posture other than NORMAL or GUARDED, such as the RESTRICTED the PDS reports for a missing or expired posture, leaves the decision undefined |
| 2 Mobile device enrolment | `BRIDGE-MOBILE-BANKING v1` | `DEVICE_ENROL`, `BALANCE_ENQUIRY` | PERMIT, STEP_UP, DENY (`BANK_SCOPE_MISMATCH`) | none |
| 3 New beneficiary cooling period | `BRIDGE-INTERNET-BANKING v1` | `ADD_BENEFICIARY`, `TRANSFER_TO_BENEFICIARY` | PERMIT, DENY (`WAIT_COOLING_PERIOD`), STEP_UP | `cooling_period_minutes` |
| 4 Teller cash withdrawal | `BRIDGE-BRANCH-BANKING v2` (v1 read the supervisor's approval from facts a client could set; v2 reads a verified completion of `REQUIRE_DUAL_CONTROL`, and the approver is compared with `teller_id`) | `CASH_WITHDRAWAL` | PERMIT, REFER (`BRANCH_LIMIT_01`, `REQUIRE_DUAL_CONTROL`), DENY (`SEGREGATION_OF_DUTIES`) | `branch_delegation_limit_inr` |
| 5 KCC evidence | `BRIDGE-KCC v1` | `KCC_ASSESS` | PERMIT (prerequisites hold), REFER (`LAND_EVIDENCE_MISMATCH`), NEED_EVIDENCE | `kcc_area_tolerance_milli_acres` |
| 6 AePS BC withdrawal | `BRIDGE-AEPS v3` | `AEPS_WITHDRAWAL` | PERMIT, REFER (`BC_EXPOSURE_LIMIT_EXCEEDED`), DENY | `daily_ceiling_inr`, `step_up_threshold_inr`, `bc_daily_exposure_limit_inr` |
| 7 BBPS biller eligibility | `BRIDGE-BBPS v1` | `BILL_PAYMENT` | PERMIT, DENY (`BILLER_NOT_ENABLED`) | `enabled_biller_classes`, `permitted_instruments` (lists of names) |

Not here, on purpose: journey 8 (internal control-plane release access) runs in the Landing Zone's Control Plane OPA,
not in the PDS; journey 9 (Inference plane) is outside the PDS. `DEFER_UNAVAILABLE` ("policy not loaded") is the PDS's own
answer, never a rule's. **Every ruleset is fail-closed on its limits**: a limit that is missing or not a whole number
leaves `decision` undefined (the PDS records `RULE_UNDEFINED`), and each rule is guarded by a positive check so that a
missing value can never let a request through. The PDS repository runs every journey through the real engine
(`tests/assembly/journeys_test.go`).

## Strings that are not reasons

The gate reads every UPPER_SNAKE string in a policy as a reason, so an operation code or an obligation reference must be
registered in `contract/reasons.json` under `literals` (`kind`: `OPERATION`, `OBLIGATION` or `POSTURE`, an L4 operating posture a rule switches on). A fact's enum values
need no registration: they come from the ruleset's `fact-schema.json`. A registered literal nothing uses, one that is also
a reason, or one for a profile not in the manifest, fails the gate.

## Conformance and promotion (PDE architecture document, component 11 and section 33)

`make conformance` runs the two checks the repository owns; `make promote-check` runs everything a ruleset must pass before
it may be signed and promoted (the gate, the tests, lint, conformance, and a vulnerability scan).

- **Mutation (`make mutate`).** Each ruleset is mutated one change at a time (a comparison turned over, a `+` turned into a `-`, a
  result turned into `PERMIT`, a dropped `not`, a flipped boolean) and its own Rego tests must fail on every mutant. A mutant that
  survives is a rule the tests do not pin down. When one is genuinely equivalent to the original, a reviewer lists it in
  `conformance/accepted-mutants.json` with the reason; a listing that no longer matches anything fails as stale. All ten
  rulesets kill every mutant today; writing the mutation check found, and the added tests now cover, among others a revoked
  device asking for a balance and the result and class of several denials that were asserted only by reason.
- **N and N-1 (`make compat`).** Each profile with two or more versions has a corpus in `conformance/compat/<profile>.json`. The
  adjacent versions answer the same inputs and a newer version may be stricter but not more permissive: any widening must be listed
  in `allowed_widening` (version pair, case, reason), and a listing that no longer happens fails as stale. A profile with two
  versions and no corpus fails. Today `BRIDGE-UPI` v5 to v6 and `BRIDGE-AEPS` v2 to v3 only narrow (a step-up, a referral, a
  denial for a BC that is not authorised).
- **Not here:** regional version skew (regions are not modelled yet) and latency (the PDS has `make bench`).
- **CI.** `.gitlab-ci.yml` runs the gate, conformance, `govulncheck` and the proposal export. It uses plain jobs because the GitLab
  project does not exist yet; align it with the shared components when it does.


## Control-plane rules (PDE architecture document component 2, Journey 8)

`control/` holds the rules the Landing Zone's Control Plane OPA runs, not the PDS: `validate_configuration/v1`, which says whether a
proposed bank configuration (L3) is technically permissible against the Service Profile's field rules and the inherited levels (L1 platform,
L2 FI class). The document's example (L1 100,000, L2 50,000) gives VALID for 20,000 and INVALID for 60,000. **VALID is evidence, never approval:**
the output is `{valid, reason_codes, rule_refs, effective, provenance}` and nothing else, and missing or partial input is INVALID
(`INPUT_INCOMPLETE`), never VALID by default. The contract is `../sspl-cip-policy-decision-service/docs/rules-contract.md`, section 11; the override
semantics are provisional (the document defines the six names, not their meaning).

The family has its own manifest (`control/manifest.template.json`, bundle `pde-control-rules`), its own registry (`contract/control-reasons.json`)
and its own gate, `rulescheck.CheckControl`, which `make check` runs after the runtime gate: the same compile, test and literal checks, a closed set of
output keys evaluated on the examples each ruleset ships (`examples.json`), registered reasons and rule references, and the separation of the two bundles
(a control package may not appear in the runtime manifest or the reverse). `make mutate` mutation-tests the control rules too.

`release_access/v1` is Journey 8: may this actor submit, approve or activate this change? The same actor approving or activating their own change is DENY
`SAME_ACTOR`; activation needs the release approver and PHOENIX gates, a `TESTPACK-` record and an approval by someone other than the author. PERMIT means the action
may be attempted, never that it is approved or done. Which role may do what is the Landing Zone's RBAC and arrives as `input.permissions`: the rules hold no role name.


## Bindings as policy data (PDE architecture document, section 13)

A published profile is bank configuration. The document says a configuration-only change needs a new signed snapshot and **never** a new bundle: "a bundle
upload must never silently activate an unapproved bank configuration". So `rules-gen -policy-data DIR` writes the bindings as a separate artefact
(`policy-data.manifest.template.json`, listing each binding file with its sha256, and `bindings/...`), and the bundle written to `-out` carries none:
**the same rules and templates always give the same bundle bytes** (tested). The policy data is signed and released on its own revision, with its own approval.
Without `-policy-data` the legacy layout (bindings in the bundle manifest) is unchanged until the PDS loads policy data (plan Task 10 in the PDS repository).

**Approved safe-reason text.** `policy-data/safe-reasons.json` holds the approved text and appeal path `GET_SAFE_REASON` returns (PDS `docs/rules-contract.md`, section 4.4b). `rules-check` refuses an entry with no `approval_ref` or `appeal_ref`, text that carries a rule or markup, and a reason no ruleset or template can return; `rules-gen -policy-data` ships the file as the `safe_reasons` document. The file is empty until the business supplies approved entries: never write text here that nobody approved.


## Pair conformance (PDE architecture document component 11)

`make pairtest` (part of `make promote-check`) runs `rules-pairtest` on `conformance/pairs/bridge_upi_v7.json`: the control rules judge each proposed configuration (the document's 20,000 is accepted, 60,000
violates the FI class limit, another bank's configuration is refused), the runtime ruleset decides under the configuration they approve (a GUARDED posture still narrows it; no posture limit or a RESTRICTED posture
is undefined), and the ruleset's and the control rules' mutation and N/N-1 checks are clean. Only a pass writes `build/testpack-upi-v7.json`, a `pde-testpack/v1` record with the id
`TESTPACK-UPI-v7-<8 hex>-PASS` and the digests of what was tested; a failure writes nothing. `pds-release -testpack-file` (PDS repository) checks the record against the policy the bundle carries.
Spec format and record: `../sspl-cip-policy-decision-service/docs/rules-contract.md`, section 4.4a.
