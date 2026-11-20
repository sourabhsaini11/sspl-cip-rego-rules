# BRIDGE-BALANCE-ENQUIRY ruleset v1 - BALANCE_ENQUIRY allowed while the customer is under the
# daily balance-enquiry quota (rule catalogue R-ACC-BAL-DAILY, "5 per calendar day").
#
# The limit arrives in input.values["R-ACC-BAL-DAILY"]: the signed state's parameter, verbatim.
# input.live.daily_drawn_inr is the customer's count of permitted enquiries today (the contract
# note on `live` in the PDS docs/rules-contract.md: for this profile the counter is a count, not
# rupees, and the writer is Core). This request is allowed if count + 1 does not pass the limit.
# No counter yet (found false) reads as 0.
#
# Not enforced here: R-ACC-BAL-VELOCITY (3 per minute; the PDE keeps no per-minute counter) and
# R-ACC-READ-DAILY (it governs ACCOUNT_DETAILS and CHEQUE_STATUS, not this operation).
#
# Rules carry no data. Input contract: v1.
# Fail closed: a missing or non-whole limit, or a counter that is not a whole number, leaves
# `decision` undefined, which the PDE records as REJECT RULE_UNDEFINED.
package cip.pde.bridge_balance_enquiry.v1

whole_number(x) if {
	is_number(x)
	x == round(x)
}

limit_ok if {
	whole_number(input.values["R-ACC-BAL-DAILY"])
	input.values["R-ACC-BAL-DAILY"] >= 0
	whole_number(input.live.daily_drawn_inr)
	input.live.daily_drawn_inr >= 0
}

decision := {
	"allow": true,
	"reason": "BALANCE_WITHIN_DAILY_QUOTA",
	"details": {},
	"obligations": {},
} if {
	limit_ok
	input.live.daily_drawn_inr + 1 <= input.values["R-ACC-BAL-DAILY"]
}

decision := {
	"allow": false,
	"reason": "BALANCE_DAILY_QUOTA_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"details": {},
	"obligations": {},
} if {
	limit_ok
	input.live.daily_drawn_inr + 1 > input.values["R-ACC-BAL-DAILY"]
}
