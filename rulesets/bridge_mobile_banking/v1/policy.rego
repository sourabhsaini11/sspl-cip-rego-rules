# BRIDGE-MOBILE-BANKING ruleset v1 - device enrolment and read-only access (PDE architecture
# document, journey 2).
#
# Operations: DEVICE_ENROL (a device the bank does not know yet) and BALANCE_ENQUIRY (read-only).
# Any other operation leaves `decision` undefined (RULE_UNDEFINED): no approved policy applies.
#
# Bank scope comes first and applies to every operation: an actor asking for another bank's
# data is a DENY with BANK_SCOPE_MISMATCH, whatever else is true.
#
# DEVICE_ENROL: a revoked device is denied; consent that is not valid is denied (CIP-POL-CONSENT);
# an unknown device steps up (an approved device binding or an independent authentication); a known
# device is permitted. BALANCE_ENQUIRY: a known device with a valid session is permitted; a read
# never invents an amount, the bank adapter proves the balance.
#
# No limits are involved, so this ruleset reads nothing from input.values. Input contract: v1.
package cip.pde.bridge_mobile_banking.v1

other_bank if input.facts.subject_bank_id != input.ctx.bank_id

decision := {
	"result": "DENY",
	"reason": "BANK_SCOPE_MISMATCH",
	"reason_code": "CIP-POL-DENY",
} if other_bank

decision := {
	"result": "DENY",
	"reason": "DEVICE_REVOKED",
	"reason_code": "CIP-POL-TRUST",
} if {
	not other_bank
	input.ctx.operation == "DEVICE_ENROL"
	input.facts.device_trust == "REVOKED"
}

decision := {
	"result": "DENY",
	"reason": "CONSENT_NOT_VALID",
	"reason_code": "CIP-POL-CONSENT",
} if {
	not other_bank
	input.ctx.operation == "DEVICE_ENROL"
	input.facts.device_trust != "REVOKED"
	input.facts.consent != "VALID"
}

decision := {
	"result": "STEP_UP",
	"reason": "DEVICE_UNVERIFIED",
	"reason_code": "CIP-POL-TRUST",
	"obligation_refs": ["DEVICE_BINDING_OR_INDEPENDENT_AUTH"],
} if {
	not other_bank
	input.ctx.operation == "DEVICE_ENROL"
	input.facts.device_trust == "UNKNOWN"
	input.facts.consent == "VALID"
}

decision := {
	"result": "PERMIT",
	"reason": "DEVICE_KNOWN",
} if {
	not other_bank
	input.ctx.operation == "DEVICE_ENROL"
	input.facts.device_trust == "KNOWN"
	input.facts.consent == "VALID"
}

decision := {
	"result": "PERMIT",
	"reason": "READ_ONLY_PERMITTED",
} if {
	not other_bank
	input.ctx.operation == "BALANCE_ENQUIRY"
	input.facts.device_trust == "KNOWN"
	input.facts.session_valid
}

decision := {
	"result": "STEP_UP",
	"reason": "SESSION_NOT_VERIFIED",
	"reason_code": "CIP-POL-TRUST",
	"obligation_refs": ["REAUTHENTICATE_SESSION"],
} if {
	not other_bank
	input.ctx.operation == "BALANCE_ENQUIRY"
	input.facts.device_trust == "KNOWN"
	not input.facts.session_valid
}

decision := {
	"result": "STEP_UP",
	"reason": "DEVICE_UNVERIFIED",
	"reason_code": "CIP-POL-TRUST",
	"obligation_refs": ["DEVICE_BINDING_OR_INDEPENDENT_AUTH"],
} if {
	not other_bank
	input.ctx.operation == "BALANCE_ENQUIRY"
	input.facts.device_trust == "UNKNOWN"
}

decision := {
	"result": "DENY",
	"reason": "DEVICE_REVOKED",
	"reason_code": "CIP-POL-TRUST",
} if {
	not other_bank
	input.ctx.operation == "BALANCE_ENQUIRY"
	input.facts.device_trust == "REVOKED"
}
