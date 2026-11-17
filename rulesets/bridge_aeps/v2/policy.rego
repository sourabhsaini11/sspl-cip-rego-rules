# BRIDGE-AEPS ruleset v2 - AEPS_WITHDRAWAL daily ceiling with a step-up obligation.
#
# Rules carry no data: ceilings arrive in input.values, the day's draw in input.live.
# Input contract: v1.
#
# Fail closed: a decision is produced only on positive proof. A missing ceiling or
# threshold leaves `decision` undefined, which the PDE records as REJECT RULE_UNDEFINED.
#
# Live counter: input.live.found == false means no counter exists. This ruleset treats
# a missing counter as nothing drawn and reports details.live_counter_found so the
# record shows which case applied. The counter's writer is an open dependency (DEP-02).
#
# The step-up obligation is evaluated on the requested amount against
# input.values.step_up_threshold_inr and travels with ALLOW and REJECT alike.
package cip.pde.bridge_aeps.v2

# Typed limits: a ceiling or threshold that is present but not a whole number is a malformed
# state document. In Rego a number sorts before a string, so a string threshold would switch
# the step-up obligation off and a string ceiling would allow everything. A malformed value
# leaves `decision` undefined, like a missing one.
whole_number(x) if {
	is_number(x)
	x == round(x)
}

malformed_limit if {
	some name in {"daily_ceiling_inr", "step_up_threshold_inr"}
	not whole_number(input.values[name])
	input.values[name]
}

drawn := input.live.daily_drawn_inr

# Never negative: a customer already over the ceiling has nothing left, not a debt.
remaining := max([0, input.values.daily_ceiling_inr - drawn])

step_up := input.facts.amount_inr > input.values.step_up_threshold_inr

obligations := {"step_up_required": step_up}

decision := {
	"allow": false,
	"reason": "INVALID_AMOUNT",
	"reason_code": "CIP-POL-DENY",
	"details": {"live_counter_found": input.live.found},
	"obligations": {"step_up_required": false},
} if {
	not malformed_limit
	input.facts.amount_inr < 1
}

decision := {
	"allow": false,
	"reason": "DAILY_CEILING_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"details": {"remaining_daily_allowance_inr": remaining, "live_counter_found": input.live.found},
	"obligations": obligations,
} if {
	not malformed_limit
	input.facts.amount_inr >= 1
	input.facts.amount_inr > remaining
}

decision := {
	"allow": true,
	"reason": "WITHIN_CEILING",
	"details": {"remaining_daily_allowance_inr": remaining - input.facts.amount_inr, "live_counter_found": input.live.found},
	"obligations": obligations,
} if {
	not malformed_limit
	input.facts.amount_inr >= 1
	input.facts.amount_inr <= remaining
}
