# BRIDGE-BRANCH-BANKING ruleset v1 - teller cash withdrawal and dual control (PDE architecture
# document, journey 4).
#
# Operation: CASH_WITHDRAWAL. Any other operation leaves `decision` undefined (RULE_UNDEFINED).
#
# A teller without the teller role is denied. A withdrawal within the branch delegation
# (input.values.branch_delegation_limit_inr) is permitted. Above it the answer is REFER with the
# obligation REQUIRE_DUAL_CONTROL and the reason BRANCH_LIMIT_01, until a supervisor's approval is
# supplied. The approval must be independent: the same person as the teller, or an approval bound to
# another intent (a replay), is a DENY with SEGREGATION_OF_DUTIES; a supervisor whose session is not
# fresh does not count and the answer stays REFER. A matching, fresh, independent approval is the
# PERMIT.
#
# Fail closed: a missing or mistyped delegation limit leaves `decision` undefined. Input contract: v1.
package cip.pde.bridge_branch_banking.v1

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

has_approval if {
	input.facts.supervisor_id
	input.facts.approval_intent_digest
}

same_person if input.facts.supervisor_id == input.facts.teller_id

replayed if input.facts.approval_intent_digest != input.facts.intent_digest

fresh if input.facts.supervisor_session_fresh == true

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
	not has_approval
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
	has_approval
	same_person
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
	has_approval
	not same_person
	replayed
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
	has_approval
	not same_person
	not replayed
	not fresh
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
	has_approval
	not same_person
	not replayed
	fresh
}
