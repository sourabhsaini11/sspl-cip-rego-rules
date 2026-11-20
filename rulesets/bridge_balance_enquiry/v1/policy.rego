# Spelling: the rule catalogue (migration 0042) and Core's defaults say BALANCE_ENQUIRY; the
# catalogue's profile seeds say BALANCE_INQUIRY (see the PDS docs/naming-map.md). This ruleset
# serves the ENQUIRY spelling; BRIDGE-BALANCE-INQUIRY v1 serves the other. Same behaviour.
#
# NOT enforced here: R-ACC-BAL-DAILY (5 per calendar day) and R-ACC-BAL-VELOCITY (3 per minute).
# The catalogue names the Switch (Core) as their enforcement point, and the PDE holds no per-
# customer request counter (its live counter is rupees drawn, not a count).
# BRIDGE-BALANCE-ENQUIRY ruleset v1 - BALANCE_ENQUIRY allowed only with the required
# authentication factor.
#
# A deliberately small third profile: it exists to show that a new profile is data (a
# ruleset directory, a fact schema, a manifest entry and registered reasons), not service
# code. It uses no amounts and no live counter.
#
# Rules carry no data: the factor the bank requires arrives in input.values.
# Input contract: v1.
#
# Fail closed: a decision is produced only on positive proof. A missing
# required_auth_factor leaves `decision` undefined, which the PDE records as REJECT
# RULE_UNDEFINED.
package cip.pde.bridge_balance_enquiry.v1

decision := {
	"allow": true,
	"reason": "AUTH_FACTOR_ACCEPTED",
	"details": {},
	"obligations": {},
} if input.facts.auth_factor == input.values.required_auth_factor

decision := {
	"allow": false,
	"reason": "AUTH_FACTOR_NOT_ACCEPTED",
	"reason_code": "CIP-POL-TRUST",
	"details": {},
	"obligations": {},
} if input.facts.auth_factor != input.values.required_auth_factor
