# BRIDGE-BBPS ruleset v1 - bill payment and biller eligibility (PDE architecture document,
# journey 7).
#
# Operation: BILL_PAYMENT. Any other operation leaves `decision` undefined (RULE_UNDEFINED).
#
# This ruleset checks the bank subscription, the biller class, the payer session and the payment
# instrument. It never calculates or certifies the biller's dues: the biller, the rail and the bank
# remain authoritative for the payment itself. An inactive subscription or an invalid session is a
# DENY; a biller class the bank has not enabled is a DENY with BILLER_NOT_ENABLED (the response
# shows a safe reason and an alternative, never a provider override); an instrument the bank does
# not permit is a DENY. A policy that is not loaded is the PDS's DEFER_UNAVAILABLE.
#
# The enabled biller classes and the permitted instruments are the bank's configuration, lists of
# names in input.values. Fail closed: a missing list, or one that is not a list of strings, leaves
# `decision` undefined. Input contract: v1.
package cip.pde.bridge_bbps.v1

name_list(x) if {
	is_array(x)
	every n in x {
		is_string(n)
	}
}

lists_ok if {
	name_list(input.values.enabled_biller_classes)
	name_list(input.values.permitted_instruments)
}

biller_enabled if input.facts.biller_class in input.values.enabled_biller_classes

instrument_permitted if input.facts.instrument in input.values.permitted_instruments

decision := {
	"result": "DENY",
	"reason": "SUBSCRIPTION_NOT_ACTIVE",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "BILL_PAYMENT"
	not input.facts.subscription_active
}

decision := {
	"result": "DENY",
	"reason": "SESSION_NOT_VALID",
	"reason_code": "CIP-POL-TRUST",
} if {
	input.ctx.operation == "BILL_PAYMENT"
	input.facts.subscription_active
	not input.facts.session_valid
}

decision := {
	"result": "DENY",
	"reason": "BILLER_NOT_ENABLED",
	"reason_code": "CIP-POL-DENY",
} if {
	input.ctx.operation == "BILL_PAYMENT"
	lists_ok
	input.facts.subscription_active
	input.facts.session_valid
	not biller_enabled
}

decision := {
	"result": "DENY",
	"reason": "INSTRUMENT_NOT_PERMITTED",
	"reason_code": "CIP-POL-DENY",
} if {
	input.ctx.operation == "BILL_PAYMENT"
	lists_ok
	input.facts.subscription_active
	input.facts.session_valid
	biller_enabled
	not instrument_permitted
}

decision := {
	"result": "PERMIT",
	"reason": "BILLER_ELIGIBLE",
} if {
	input.ctx.operation == "BILL_PAYMENT"
	lists_ok
	input.facts.subscription_active
	input.facts.session_valid
	biller_enabled
	instrument_permitted
}
