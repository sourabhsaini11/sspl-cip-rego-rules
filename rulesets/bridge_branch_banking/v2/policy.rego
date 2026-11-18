# BRIDGE-BRANCH-BANKING ruleset v2 - teller cash withdrawal and dual control (PDE architecture document,
# journey 4, and section 8).
#
# Operation: CASH_WITHDRAWAL. Any other operation leaves `decision` undefined (RULE_UNDEFINED).
#
# What changed from v1: the supervisor's approval is no longer a fact the branch system sends. v1 read
# `supervisor_id`, `supervisor_session_fresh` and `approval_intent_digest` from the request, which a client
# could set: section 8 says no enforcement point may turn a REFER into a PERMIT by changing a flag, and
# obligations need verified completion at the same bank, provider, actor, purpose, request intent, Policy_Ref
# and effective-state version. In v2 the approval is a completion of REQUIRE_DUAL_CONTROL in ctx.completions,
# which the PDS gives the rules only after verifying it (MAC through the KMI, bound to the request and the
# original decision, not expired, used once; docs/rules-contract.md, section 4.4). Replay and freshness are
# therefore the PDS's, and the rules only judge who approved.
#
# A teller without the teller role is denied. A withdrawal within the branch delegation
# (input.values.branch_delegation_limit_inr) is permitted. Above it the answer is REFER with the obligation
# REQUIRE_DUAL_CONTROL and the reason BRANCH_LIMIT_01 until a verified completion exists. A completion by the
# teller (completed_by is the same opaque actor id as facts.teller_id) is a DENY SEGREGATION_OF_DUTIES; any
# other is the PERMIT.
#
# Fail closed: a missing or mistyped delegation limit leaves `decision` undefined. Input contract: v1.
package cip.pde.bridge_branch_banking.v2

whole_number(x) if {
	is_number(x)
	x == round(x)
}

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.branch_delegation_limit_inr)
}

above_delegation if input.facts.amount_inr > input.values.branch_delegation_limit_inr

dual_control_done := [c |
	some c in input.ctx.completions
	c.obligation_ref == "REQUIRE_DUAL_CONTROL"
]

has_completion if count(dual_control_done) > 0

# Any approver who is the teller is a breach, even beside an independent one.
approver_is_teller if {
	some c in dual_control_done
	c.completed_by == input.facts.teller_id
}

decision := {
	"result": "DENY",
	"reason": "ROLE_NOT_AUTHORISED",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	not input.facts.teller_role_valid
}

decision := {
	"result": "DENY",
	"reason": "INVALID_AMOUNT",
	"reason_code": "CIP-POL-DENY",
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	input.facts.teller_role_valid
	input.facts.amount_inr < 1
}

decision := {
	"result": "PERMIT",
	"reason": "WITHIN_DELEGATION",
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	limits_ok
	input.facts.teller_role_valid
	input.facts.amount_inr >= 1
	not above_delegation
}

decision := {
	"result": "REFER",
	"reason": "BRANCH_LIMIT_01",
	"reason_code": "CIP-POL-LIMIT",
	"obligation_refs": ["REQUIRE_DUAL_CONTROL"],
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	limits_ok
	input.facts.teller_role_valid
	input.facts.amount_inr >= 1
	above_delegation
	not has_completion
}

decision := {
	"result": "DENY",
	"reason": "SEGREGATION_OF_DUTIES",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	limits_ok
	input.facts.teller_role_valid
	input.facts.amount_inr >= 1
	above_delegation
	has_completion
	approver_is_teller
}

decision := {
	"result": "PERMIT",
	"reason": "DUAL_CONTROL_SATISFIED",
} if {
	input.ctx.operation == "CASH_WITHDRAWAL"
	limits_ok
	input.facts.teller_role_valid
	input.facts.amount_inr >= 1
	above_delegation
	has_completion
	not approver_is_teller
}
