package cip.pde.bridge_mobile_banking.v1_test

import data.cip.pde.bridge_mobile_banking.v1 as mb

# Journey 2: a new device DVC-43 for a KGB001 customer; a known device asking for a balance; the same
# actor asking for another bank's data.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-MOBILE-BANKING", "operation": "DEVICE_ENROL", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"device_trust": "UNKNOWN", "consent": "VALID", "session_valid": true, "subject_bank_id": "KGB001"},
	"values": {},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

op(o) := object.union(base, {"ctx": {"operation": o}})

fact(k, v) := object.union(base, {"facts": {k: v}})

test_new_device_steps_up if {
	d := mb.decision with input as base
	d.result == "STEP_UP"
	d.reason == "DEVICE_UNVERIFIED"
	d.obligation_refs == ["DEVICE_BINDING_OR_INDEPENDENT_AUTH"]
}

test_known_device_balance_is_permitted if {
	i := object.union(op("BALANCE_ENQUIRY"), {"facts": {"device_trust": "KNOWN"}})
	d := mb.decision with input as i
	d.result == "PERMIT"
	d.reason == "READ_ONLY_PERMITTED"
}

test_another_banks_data_is_denied_for_every_operation if {
	every o in {"DEVICE_ENROL", "BALANCE_ENQUIRY"} {
		d := mb.decision with input as object.union(op(o), {"facts": {"subject_bank_id": "KGB002", "device_trust": "KNOWN"}})
		d.result == "DENY"
		d.reason == "BANK_SCOPE_MISMATCH"
	}
}

test_consent_that_is_not_valid_is_denied if {
	d := mb.decision with input as fact("consent", "EXPIRED")
	d.result == "DENY"
	d.reason == "CONSENT_NOT_VALID"
	d.reason_code == "CIP-POL-CONSENT"
}

test_a_revoked_device_is_denied if {
	d := mb.decision with input as fact("device_trust", "REVOKED")
	d.result == "DENY"
	d.reason == "DEVICE_REVOKED"
}

test_a_known_device_with_consent_enrols if {
	d := mb.decision with input as fact("device_trust", "KNOWN")
	d.result == "PERMIT"
}

test_a_balance_without_a_valid_session_steps_up if {
	i := object.union(op("BALANCE_ENQUIRY"), {"facts": {"device_trust": "KNOWN", "session_valid": false}})
	d := mb.decision with input as i
	d.result == "STEP_UP"
	d.reason == "SESSION_NOT_VERIFIED"
}

test_an_unknown_device_asking_for_a_balance_steps_up if {
	d := mb.decision with input as op("BALANCE_ENQUIRY")
	d.result == "STEP_UP"
}

test_an_operation_nobody_approved_is_undefined if {
	not mb.decision with input as op("EXPORT_STATEMENT")
}
