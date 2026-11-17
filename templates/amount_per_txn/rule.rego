# AMOUNT_PER_TXN template (P1): the amount of one transaction may not exceed a limit.
#
# Generic: the limit is not in this file. The binding names the key to read
# (input.rule.value_key) and the number comes from input.values, the bank's signed state.
# The PDS hands this template the same input as a ruleset plus input.rule.
#
# Fail closed: a missing, mistyped or fractional limit, or a non-numeric amount, leaves
# `decision` undefined (the PDS records a REJECT RULE_UNDEFINED). In Rego a number sorts
# before a string, so `amount <= "100000"` is true; the guards below keep that from allowing.
package cip.pde.template.amount_per_txn

limit := input.values[input.rule.value_key]

valid_limit if {
	is_number(limit)
	limit == round(limit)
}

valid_amount if is_number(input.facts.amount_inr)

decision := {"allow": true, "reason": "AMOUNT_WITHIN_LIMIT"} if {
	valid_limit
	valid_amount
	input.facts.amount_inr <= limit
}

decision := {
	"allow": false,
	"reason": "AMOUNT_OVER_LIMIT",
	"reason_code": "CIP-POL-LIMIT",
	"details": {"rule_id": input.rule.rule_id},
} if {
	valid_limit
	valid_amount
	input.facts.amount_inr > limit
}
