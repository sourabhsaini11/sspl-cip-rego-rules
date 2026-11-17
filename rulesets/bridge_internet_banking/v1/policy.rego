# BRIDGE-INTERNET-BANKING ruleset v1 - new beneficiary and its cooling period (PDE architecture
# document, journey 3).
#
# Operations: ADD_BENEFICIARY (registration) and TRANSFER_TO_BENEFICIARY (the first and later
# transfers). Any other operation leaves `decision` undefined (RULE_UNDEFINED).
#
# The cooling period is the bank's configuration: input.values.cooling_period_minutes, a whole
# number. The age of the beneficiary arrives as a fact in minutes (the adapter measures it), so this
# ruleset needs no clock arithmetic. A transfer inside the period is a DENY with WAIT_COOLING_PERIOD
# and the minutes still to wait; the period is never skipped. A policy that is unavailable is the
# PDS's DEFER_UNAVAILABLE, never a decision made here.
#
# Fail closed: a missing or mistyped cooling period leaves `decision` undefined. Input contract: v1.
package cip.pde.bridge_internet_banking.v1

whole_number(x) if {
	is_number(x)
	x == round(x)
}

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.cooling_period_minutes)
}

cooled if input.facts.beneficiary_age_minutes >= input.values.cooling_period_minutes

remaining := input.values.cooling_period_minutes - input.facts.beneficiary_age_minutes

decision := {
	"result": "PERMIT",
	"reason": "REGISTRATION_PERMITTED",
} if {
	input.ctx.operation == "ADD_BENEFICIARY"
	input.facts.maker_authenticated
	input.facts.beneficiary_verified
}

decision := {
	"result": "DENY",
	"reason": "REGISTRATION_NOT_VERIFIED",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "ADD_BENEFICIARY"
	not registration_verified
}

registration_verified if {
	input.facts.maker_authenticated
	input.facts.beneficiary_verified
}

decision := {
	"result": "DENY",
	"reason": "WAIT_COOLING_PERIOD",
	"reason_code": "CIP-POL-DENY",
	"details": {"remaining_minutes": remaining},
} if {
	input.ctx.operation == "TRANSFER_TO_BENEFICIARY"
	limits_ok
	not cooled
}

decision := {
	"result": "DENY",
	"reason": "BENEFICIARY_CHANGED",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "TRANSFER_TO_BENEFICIARY"
	limits_ok
	cooled
	not input.facts.beneficiary_unchanged
}

decision := {
	"result": "STEP_UP",
	"reason": "MFA_REQUIRED",
	"reason_code": "CIP-POL-TRUST",
	"obligation_refs": ["MFA_FOR_TRANSFER"],
} if {
	input.ctx.operation == "TRANSFER_TO_BENEFICIARY"
	limits_ok
	cooled
	input.facts.beneficiary_unchanged
	not input.facts.mfa_valid
}

decision := {
	"result": "PERMIT",
	"reason": "TRANSFER_PERMITTED",
} if {
	input.ctx.operation == "TRANSFER_TO_BENEFICIARY"
	limits_ok
	cooled
	input.facts.beneficiary_unchanged
	input.facts.mfa_valid
}
