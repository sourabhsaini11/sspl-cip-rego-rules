package cip.pde.bridge_internet_banking.v1_test

import data.cip.pde.bridge_internet_banking.v1 as ib

# Journey 3: beneficiary BEN-014 added at 10:00; a dummy six-hour (360 minute) cooling period.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-INTERNET-BANKING", "operation": "TRANSFER_TO_BENEFICIARY", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"maker_authenticated": true, "beneficiary_verified": true, "beneficiary_age_minutes": 90, "mfa_valid": true, "beneficiary_unchanged": true},
	"values": {"cooling_period_minutes": 360},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

age(m) := object.union(base, {"facts": {"beneficiary_age_minutes": m}})

test_registration_by_an_authenticated_maker_is_permitted if {
	d := ib.decision with input as object.union(base, {"ctx": {"operation": "ADD_BENEFICIARY"}})
	d.result == "PERMIT"
	d.reason == "REGISTRATION_PERMITTED"
}

test_registration_without_verification_is_denied if {
	i := object.union(base, {"ctx": {"operation": "ADD_BENEFICIARY"}, "facts": {"beneficiary_verified": false}})
	d := ib.decision with input as i
	d.result == "DENY"
	d.reason == "REGISTRATION_NOT_VERIFIED"
}

test_a_transfer_inside_the_period_waits if {
	d := ib.decision with input as base
	d.result == "DENY"
	d.reason == "WAIT_COOLING_PERIOD"
	d.details.remaining_minutes == 270
}

test_a_transfer_after_the_period_is_permitted if {
	d := ib.decision with input as age(400)
	d.result == "PERMIT"
	d.reason == "TRANSFER_PERMITTED"
}

test_the_period_ends_exactly_at_the_minimum if {
	ib.decision.result == "PERMIT" with input as age(360)
	ib.decision.reason == "WAIT_COOLING_PERIOD" with input as age(359)
}

test_a_changed_beneficiary_is_denied if {
	d := ib.decision with input as object.union(age(400), {"facts": {"beneficiary_unchanged": false}})
	d.reason == "BENEFICIARY_CHANGED"
}

test_an_invalid_mfa_steps_up if {
	d := ib.decision with input as object.union(age(400), {"facts": {"mfa_valid": false}})
	d.result == "STEP_UP"
	d.obligation_refs == ["MFA_FOR_TRANSFER"]
}

test_a_missing_period_is_undefined if {
	not ib.decision with input as object.union(base, {"values": {"cooling_period_minutes": "360"}})
	i := json.remove(base, ["values/cooling_period_minutes"])
	not ib.decision with input as i
}

test_a_changed_beneficiary_is_a_deny_with_a_trust_class if {
	d := ib.decision with input as object.union(age(400), {"facts": {"beneficiary_unchanged": false}})
	d.result == "DENY"
	d.reason_code == "CIP-POL-TRUST"
}
