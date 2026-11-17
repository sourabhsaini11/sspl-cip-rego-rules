# Contract version

These rules are written for **input contract `v1`** (`rulesets/manifest.template.json`,
`input_contract`; `rulescheck.SupportedInputContract`).

The contract itself, the one the PDS builds and enforces, is **not copied here**. It lives in the PDS repository
so there is one version of it: `sspl-cip-policy-decision-service/docs/rules-contract.md`.

`reasons.json` is this repository's registry of the reasons the rules may return. It is generated from the PDS's
reference registry at creation (2026-11-03) and owned here from then on. `reserved_for_pds` lists the two reasons
only the PDS may produce (`POLICY_REF_MISMATCH`, `RULE_UNDEFINED`).

## Moving to a new input contract

The PDS and this repository move together; see section 9 of the contract. In this repository: change
`SupportedInputContract`, the manifest's `input_contract` and the rules, in one merge request, and release it
only after a PDS that builds the new contract is deployed. A bundle for a contract the PDS does not build is
refused at load, so the order matters.
