package cip.pde.bridge_bbps.v1_test

import data.cip.pde.bridge_bbps.v1 as bbps

# Journey 7: a dummy utility payment for biller code BILLER-X09 (class UTILITY).
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-BBPS", "operation": "BILL_PAYMENT", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 1250, "biller_class": "UTILITY", "instrument": "ACCOUNT_DEBIT", "session_valid": true, "subscription_active": true},
	"values": {"enabled_biller_classes": ["UTILITY", "TELECOM"], "permitted_instruments": ["ACCOUNT_DEBIT"]},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

test_an_eligible_biller_is_permitted if {
	d := bbps.decision with input as base
	d.result == "PERMIT"
	d.reason == "BILLER_ELIGIBLE"
}

test_a_biller_class_the_bank_has_not_enabled_is_denied if {
	d := bbps.decision with input as object.union(base, {"facts": {"biller_class": "INSURANCE"}})
	d.result == "DENY"
	d.reason == "BILLER_NOT_ENABLED"
}

test_an_instrument_the_bank_does_not_permit_is_denied if {
	d := bbps.decision with input as object.union(base, {"facts": {"instrument": "CREDIT_LINE"}})
	d.reason == "INSTRUMENT_NOT_PERMITTED"
}

test_an_inactive_subscription_is_denied if {
	d := bbps.decision with input as object.union(base, {"facts": {"subscription_active": false}})
	d.reason == "SUBSCRIPTION_NOT_ACTIVE"
}

test_an_invalid_session_is_denied if {
	d := bbps.decision with input as object.union(base, {"facts": {"session_valid": false}})
	d.reason == "SESSION_NOT_VALID"
}

test_a_missing_or_malformed_list_is_undefined if {
	not bbps.decision with input as json.remove(base, ["values/enabled_biller_classes"])
	not bbps.decision with input as object.union(base, {"values": {"enabled_biller_classes": "UTILITY"}})
	not bbps.decision with input as object.union(base, {"values": {"permitted_instruments": [1]}})
}

test_another_operation_is_undefined if {
	not bbps.decision with input as object.union(base, {"ctx": {"operation": "BILL_FETCH"}})
}
