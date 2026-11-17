package cip.pde.bridge_balance_inquiry.v1_test

import data.cip.pde.bridge_balance_inquiry.v1 as bal

base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-BALANCE-INQUIRY", "operation": "BALANCE_INQUIRY", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"auth_factor": "OTP", "channel": "MOBILE"},
	"values": {"required_auth_factor": "OTP"},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

test_allow_when_the_factor_is_the_required_one if {
	d := bal.decision with input as base
	d.allow
	d.reason == "AUTH_FACTOR_ACCEPTED"
}

test_reject_when_the_factor_differs if {
	d := bal.decision with input as object.union(base, {"facts": {"auth_factor": "PIN"}})
	not d.allow
	d.reason == "AUTH_FACTOR_NOT_ACCEPTED"
	d.reason_code == "CIP-POL-TRUST"
}

test_the_required_factor_is_data_not_code if {
	bio := object.union(base, {"values": {"required_auth_factor": "BIO_FP"}})
	refused := bal.decision with input as bio
	not refused.allow
	accepted := bal.decision with input as object.union(bio, {"facts": {"auth_factor": "BIO_FP"}})
	accepted.allow
}

test_missing_required_factor_is_undefined_never_an_allow if {
	no_values := object.remove(base, ["values"])
	not bal.decision with input as no_values
	empty_values := object.union(no_values, {"values": {}})
	not bal.decision with input as empty_values
}
