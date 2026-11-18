package cip.pde.control.validate_configuration.v1_test

import data.cip.pde.control.validate_configuration.v1 as vc

# The document's example (section 3, step 2): L1 platform maximum 1,00,000, L2 FI class maximum 50,000, the bank asks for
# 20,000: VALID, effective 20,000. 60,000 violates L2. The values are the document's dummy examples.
schema := {"ref": "BRIDGE-UPI@1.2", "fields": {
	"per_txn_limit_inr": {"override": "BANK_NARROW_ONLY", "type": "int"},
	"scheme_floor_inr": {"override": "NO_OVERRIDE", "type": "int"},
	"audit_level": {"override": "PLATFORM_ONLY", "type": "string"},
	"fi_channel_cap_inr": {"override": "FI_NARROW_ONLY", "type": "int"},
	"daily_limit_inr": {"override": "BANK_WITHIN_RANGE", "type": "int", "range": {"min": 1000, "max": 100000}},
	"device_trust": {"override": "RUNTIME_FACT", "type": "string"},
	"cooling_period_minutes": {"override": "BANK_NARROW_ONLY", "type": "int", "narrows": "up"},
	"posture_label": {"override": "BANK_NARROW_ONLY", "type": "enum", "enum": ["NORMAL", "GUARDED"]},
}}

base := {
	"ctx": {
		"now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata", "bank_id": "KGB001", "bundle_revision": "2026.10.15-1",
		"maker": {"id": "MKR-1", "role": "PRODUCT_OFFICER", "bank_id": "KGB001"},
	},
	"schema": schema,
	"levels": {
		"L1": {
			"per_txn_limit_inr": 100000, "scheme_floor_inr": 1, "audit_level": "FULL", "fi_channel_cap_inr": 100000,
			"daily_limit_inr": 100000, "cooling_period_minutes": 60,
		},
		"L2": {"per_txn_limit_inr": 50000},
		"L3": {"bank_id": "KGB001", "config_ref": "CFG-KGB001-UPI-v4", "values": {"per_txn_limit_inr": 20000}},
	},
}

proposing(values) := object.union(base, {"levels": {"L3": {"values": values}}})

at_l2(values) := object.union(base, {"levels": {"L2": values}})

reasons(d) := {r | some r in d.reason_codes}

refs(d) := {r | some r in d.rule_refs}

test_the_documents_20000_limit_is_valid_and_effective if {
	d := vc.decision with input as base
	d.valid == true
	d.reason_codes == []
	d.rule_refs == []
	d.effective.per_txn_limit_inr == 20000
	d.provenance.per_txn_limit_inr == "L3"
}

test_the_documents_60000_limit_violates_the_fi_class if {
	d := vc.decision with input as proposing({"per_txn_limit_inr": 60000})
	d.valid == false
	reasons(d) == {"WIDENS_INHERITED_VALUE"}
	refs(d) == {"RULE-OVR-002"}
	d.effective == {}
}

test_a_proposal_equal_to_the_inherited_bound_is_valid if {
	d := vc.decision with input as proposing({"per_txn_limit_inr": 50000})
	d.valid == true
	d.effective.per_txn_limit_inr == 50000
}

test_one_rupee_over_the_inherited_bound_is_invalid if {
	d := vc.decision with input as proposing({"per_txn_limit_inr": 50001})
	d.valid == false
}

test_the_effective_value_falls_back_to_l2_then_l1 if {
	# object.union merges, so an empty proposal is built by replacing the level, not by unioning an empty map.
	no_l3 := json.patch(base, [{"op": "replace", "path": "/levels/L3/values", "value": {}}])
	d := vc.decision with input as no_l3
	d.valid == true
	d.effective.per_txn_limit_inr == 50000
	d.provenance.per_txn_limit_inr == "L2"
	no_l2 := json.patch(no_l3, [{"op": "replace", "path": "/levels/L2", "value": {}}])
	e := vc.decision with input as no_l2
	e.effective.per_txn_limit_inr == 100000
	e.provenance.per_txn_limit_inr == "L1"
}

test_a_narrower_l2_is_valid_and_a_wider_l2_is_not if {
	ok := vc.decision with input as at_l2({"per_txn_limit_inr": 40000})
	ok.valid == true
	wide := vc.decision with input as at_l2({"per_txn_limit_inr": 150000})
	wide.valid == false
	reasons(wide) == {"WIDENS_INHERITED_VALUE"}
}

test_a_minimum_narrows_upwards if {
	ok := vc.decision with input as proposing({"cooling_period_minutes": 360})
	ok.valid == true
	ok.effective.cooling_period_minutes == 360
	shorter := vc.decision with input as proposing({"cooling_period_minutes": 30})
	shorter.valid == false
	reasons(shorter) == {"WIDENS_INHERITED_VALUE"}
}

test_no_override_cannot_be_changed_at_any_level if {
	l3 := vc.decision with input as proposing({"scheme_floor_inr": 2})
	l3.valid == false
	reasons(l3) == {"OVERRIDE_NOT_PERMITTED"}
	refs(l3) == {"RULE-OVR-001"}
	l2 := vc.decision with input as at_l2({"scheme_floor_inr": 2})
	reasons(l2) == {"OVERRIDE_NOT_PERMITTED"}
}

test_no_override_may_repeat_the_platform_value if {
	d := vc.decision with input as proposing({"scheme_floor_inr": 1})
	d.valid == true
}

test_platform_only_is_closed_to_the_fi_class_and_the_bank if {
	l3 := vc.decision with input as proposing({"audit_level": "OFF"})
	reasons(l3) == {"OVERRIDE_NOT_PERMITTED"}
	l2 := vc.decision with input as at_l2({"audit_level": "OFF"})
	reasons(l2) == {"OVERRIDE_NOT_PERMITTED"}
}

test_fi_narrow_only_lets_the_fi_class_narrow_but_not_the_bank if {
	fi := vc.decision with input as at_l2({"fi_channel_cap_inr": 80000})
	fi.valid == true
	bank := vc.decision with input as proposing({"fi_channel_cap_inr": 80000})
	bank.valid == false
	reasons(bank) == {"OVERRIDE_NOT_PERMITTED"}
}

test_bank_within_range_accepts_a_value_inside_the_range if {
	d := vc.decision with input as proposing({"daily_limit_inr": 50000})
	d.valid == true
	d.effective.daily_limit_inr == 50000
}

test_bank_within_range_refuses_a_value_outside_the_range if {
	below := vc.decision with input as proposing({"daily_limit_inr": 999})
	reasons(below) == {"OUT_OF_RANGE"}
	refs(below) == {"RULE-RNG-001"}
	edge := vc.decision with input as proposing({"daily_limit_inr": 1000})
	edge.valid == true
}

test_the_top_of_the_range_is_inclusive_and_above_it_is_wider_than_the_bound if {
	top := vc.decision with input as proposing({"daily_limit_inr": 100000})
	top.valid == true
	above := vc.decision with input as proposing({"daily_limit_inr": 100001})
	above.valid == false
	reasons(above) == {"OUT_OF_RANGE", "WIDENS_INHERITED_VALUE"}
}

test_a_bank_within_range_field_without_a_range_is_invalid if {
	v := json.remove(proposing({"daily_limit_inr": 50000}), ["schema/fields/daily_limit_inr/range"])
	d := vc.decision with input as v
	reasons(d) == {"OUT_OF_RANGE"}
}

test_a_runtime_fact_cannot_be_stored_at_any_level if {
	for_l3 := vc.decision with input as proposing({"device_trust": "VERIFIED"})
	reasons(for_l3) == {"RUNTIME_FACT_NOT_STORABLE"}
	refs(for_l3) == {"RULE-RTF-001"}
	for_l2 := vc.decision with input as at_l2({"device_trust": "VERIFIED"})
	reasons(for_l2) == {"RUNTIME_FACT_NOT_STORABLE"}
	for_l1 := vc.decision with input as object.union(base, {"levels": {"L1": {"device_trust": "VERIFIED"}}})
	reasons(for_l1) == {"RUNTIME_FACT_NOT_STORABLE"}
}

test_a_proposal_for_another_bank_is_invalid if {
	d := vc.decision with input as object.union(base, {"levels": {"L3": {"bank_id": "KGB002"}}})
	reasons(d) == {"TENANCY_MISMATCH"}
	refs(d) == {"RULE-TEN-001"}
}

test_a_maker_from_another_bank_is_invalid if {
	d := vc.decision with input as object.union(base, {"ctx": {"maker": {"bank_id": "KGB002"}}})
	reasons(d) == {"TENANCY_MISMATCH"}
}

test_a_field_the_schema_does_not_declare_is_invalid if {
	d := vc.decision with input as proposing({"made_up_limit_inr": 5})
	reasons(d) == {"UNKNOWN_FIELD"}
	refs(d) == {"RULE-SCH-001"}
}

test_an_unknown_override_type_is_invalid if {
	v := object.union(base, {"schema": {"fields": {"per_txn_limit_inr": {"override": "ROLE_OR_PURPOSE_NARROW_ONLY"}}}})
	d := vc.decision with input as v
	reasons(d) == {"UNKNOWN_OVERRIDE_TYPE"}
	refs(d) == {"RULE-OVR-003"}
}

test_a_value_of_the_wrong_type_is_invalid if {
	string_for_int := vc.decision with input as proposing({"per_txn_limit_inr": "20000"})
	reasons(string_for_int) == {"TYPE_MISMATCH"}
	refs(string_for_int) == {"RULE-TYP-001"}
	fraction := vc.decision with input as proposing({"per_txn_limit_inr": 20000.5})
	reasons(fraction) == {"TYPE_MISMATCH"}
	not_in_enum := vc.decision with input as proposing({"posture_label": "WIDE_OPEN"})
	reasons(not_in_enum) == {"TYPE_MISMATCH"}
}

test_an_enum_value_inside_the_enum_is_typed_correctly if {
	d := vc.decision with input as proposing({"posture_label": "NORMAL"})
	d.valid == false # NORMAL has no L1 bound to narrow, so it widens nothing it can be compared with
	reasons(d) == {"WIDENS_INHERITED_VALUE"}
}

test_every_failure_is_reported_not_only_the_first if {
	d := vc.decision with input as proposing({"per_txn_limit_inr": 60000, "scheme_floor_inr": 2, "device_trust": "X"})
	d.valid == false
	reasons(d) == {"WIDENS_INHERITED_VALUE", "OVERRIDE_NOT_PERMITTED", "RUNTIME_FACT_NOT_STORABLE"}
}

test_missing_input_is_invalid_never_valid_by_default if {
	every part in ["ctx/maker/id", "ctx/bank_id", "schema/fields", "levels/L1", "levels/L2", "levels/L3/bank_id", "levels/L3/values"] {
		d := vc.decision with input as json.remove(base, [part])
		d.valid == false
		reasons(d) == {"INPUT_INCOMPLETE"}
		refs(d) == {"RULE-INP-001"}
	}
}

test_an_empty_input_is_invalid if {
	d := vc.decision with input as {}
	d.valid == false
	reasons(d) == {"INPUT_INCOMPLETE"}
}

test_an_incomplete_input_has_no_effective_values if {
	d := vc.decision with input as json.remove(base, ["ctx/maker/id"])
	d.effective == {}
	d.provenance == {}
}

test_a_valid_result_carries_no_approval_and_only_the_closed_keys if {
	d := vc.decision with input as base
	{k | some k, _ in d} == {"valid", "reason_codes", "rule_refs", "effective", "provenance"}
}

test_a_runtime_fact_is_not_part_of_the_effective_configuration if {
	d := vc.decision with input as base
	not d.effective.device_trust
}

# ---- boundaries and corners the mutation check found ----

with_fields(extra) := object.union(base, {"schema": {"fields": extra}})

test_an_empty_field_list_is_incomplete if {
	d := vc.decision with input as json.patch(base, [{"op": "replace", "path": "/schema/fields", "value": {}}])
	reasons(d) == {"INPUT_INCOMPLETE"}
}

test_a_single_declared_field_is_enough if {
	only := json.patch(base, [
		{"op": "replace", "path": "/schema/fields", "value": {"per_txn_limit_inr": {"override": "BANK_NARROW_ONLY", "type": "int"}}},
		{"op": "replace", "path": "/levels/L1", "value": {"per_txn_limit_inr": 100000}},
	])
	d := vc.decision with input as only
	d.valid == true
}

test_a_minimum_equal_to_the_inherited_value_is_valid if {
	d := vc.decision with input as proposing({"cooling_period_minutes": 60})
	d.valid == true
	d.effective.cooling_period_minutes == 60
}

test_a_boolean_field_is_typed_as_a_boolean if {
	v := with_fields({"two_factor_required": {"override": "NO_OVERRIDE", "type": "bool"}})
	ok := object.union(v, {"levels": {"L1": {"two_factor_required": true}, "L3": {"values": {"two_factor_required": true}}}})
	d := vc.decision with input as ok
	d.valid == true
	bad := object.union(v, {"levels": {"L1": {"two_factor_required": true}, "L3": {"values": {"two_factor_required": "yes"}}}})
	reasons(vc.decision) == {"OVERRIDE_NOT_PERMITTED", "TYPE_MISMATCH"} with input as bad
}

test_a_string_field_is_typed_as_a_string if {
	bad := proposing({"audit_level": 5})
	reasons(vc.decision) == {"OVERRIDE_NOT_PERMITTED", "TYPE_MISMATCH"} with input as bad
}

test_the_fi_class_may_repeat_a_no_override_value if {
	d := vc.decision with input as at_l2({"scheme_floor_inr": 1})
	d.valid == true
}

test_a_no_override_field_the_platform_never_set_cannot_be_set_by_the_fi_class if {
	v := with_fields({"orphan_floor": {"override": "NO_OVERRIDE", "type": "int"}})
	d := vc.decision with input as object.union(v, {"levels": {"L2": {"orphan_floor": 5}}})
	reasons(d) == {"OVERRIDE_NOT_PERMITTED"}
}

test_a_no_override_field_the_platform_never_set_cannot_be_set_by_the_bank if {
	v := with_fields({"orphan_floor": {"override": "NO_OVERRIDE", "type": "int"}})
	d := vc.decision with input as object.union(v, {"levels": {"L3": {"values": {"orphan_floor": 5}}}})
	reasons(d) == {"OVERRIDE_NOT_PERMITTED"}
}

test_a_narrowing_field_the_platform_never_bounded_cannot_be_set if {
	v := with_fields({"unbounded_cap": {"override": "FI_NARROW_ONLY", "type": "int"}})
	d := vc.decision with input as object.union(v, {"levels": {"L2": {"unbounded_cap": 5}}})
	reasons(d) == {"WIDENS_INHERITED_VALUE"}
}
