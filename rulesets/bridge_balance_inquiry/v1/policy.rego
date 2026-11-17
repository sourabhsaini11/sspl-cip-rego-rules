# BRIDGE-BALANCE-INQUIRY ruleset v1 - BALANCE_INQUIRY allowed only with the required
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
package cip.pde.bridge_balance_inquiry.v1

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
