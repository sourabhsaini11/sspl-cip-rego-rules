# Control plane: validate_configuration v1 (PDE architecture document component 2, sections 7.2, 11 and 33, Appendix B).
#
# The Landing Zone's Configuration Policy Validator asks: is this proposed bank configuration (L3) technically permissible
# against the Service Profile's field rules and the inherited levels (L1 platform and profile, L2 FI class)? The answer is
# VALID or INVALID with rule references. VALID is evidence, never approval, activation or effect: the output has no such
# field, and the gate checks the output keys. Missing, partial or malformed input is INVALID (INPUT_INCOMPLETE), never VALID
# by default (section 29).
#
# The rules carry no data: the schema, the levels and the proposal arrive in the input. Nothing here is a limit.
# Contract: docs/rules-contract.md (PDS repository), section 11. Provisional: the override semantics are ours.
package cip.pde.control.validate_configuration.v1

known_overrides := {"NO_OVERRIDE", "PLATFORM_ONLY", "FI_NARROW_ONLY", "BANK_NARROW_ONLY", "BANK_WITHIN_RANGE", "RUNTIME_FACT"}

# ---- completeness -------------------------------------------------------------------------------

filled(s) if {
	is_string(s)
	s != ""
}

input_ok if {
	filled(input.ctx.bank_id)
	filled(input.ctx.maker.id)
	filled(input.ctx.maker.bank_id)
	filled(input.levels.L3.bank_id)
	is_object(input.schema.fields)
	count(input.schema.fields) > 0
	is_object(input.levels.L1)
	is_object(input.levels.L2)
	is_object(input.levels.L3.values)
}

# ---- levels and fields --------------------------------------------------------------------------

l1_set(f) if f in object.keys(input.levels.L1)

l2_set(f) if f in object.keys(input.levels.L2)

l3_set(f) if f in object.keys(input.levels.L3.values)

declared(f) if input.schema.fields[f]

override_of(f) := input.schema.fields[f].override

narrows_of(f) := object.get(input.schema.fields[f], "narrows", "down")

# "b is no wider than a" in the field's own direction: a limit narrows down, a minimum narrows up.
no_wider(f, b, a) if {
	narrows_of(f) == "down"
	b <= a
}

no_wider(f, b, a) if {
	narrows_of(f) == "up"
	b >= a
}

# What the bank's value must not exceed: the FI class's value when it set one, else the platform's.
inherited(f) := input.levels.L2[f] if l2_set(f)

inherited(f) := input.levels.L1[f] if {
	not l2_set(f)
	l1_set(f)
}

has_bound(f) if l1_set(f)

has_bound(f) if l2_set(f)

typed(f, v) if {
	input.schema.fields[f].type == "int"
	is_number(v)
	v == round(v)
}

typed(f, v) if {
	input.schema.fields[f].type == "bool"
	is_boolean(v)
}

typed(f, v) if {
	input.schema.fields[f].type == "string"
	is_string(v)
}

typed(f, v) if {
	input.schema.fields[f].type == "enum"
	v in input.schema.fields[f].enum
}

# ---- violations: each one a reason and a rule reference ----------------------------------------------

violation(reason, ref) := {"reason": reason, "rule": ref}

violations contains violation("TENANCY_MISMATCH", "RULE-TEN-001") if input.levels.L3.bank_id != input.ctx.bank_id

violations contains violation("TENANCY_MISMATCH", "RULE-TEN-001") if input.ctx.maker.bank_id != input.ctx.bank_id

all_keys := object.keys(object.union(object.union(input.levels.L1, input.levels.L2), input.levels.L3.values))

violations contains violation("UNKNOWN_FIELD", "RULE-SCH-001") if {
	some f in all_keys
	not declared(f)
}

violations contains violation("UNKNOWN_OVERRIDE_TYPE", "RULE-OVR-003") if {
	some f, spec in input.schema.fields
	not spec.override in known_overrides
}

violations contains violation("TYPE_MISMATCH", "RULE-TYP-001") if {
	some f in all_keys
	declared(f)
	some lvl in ["L1", "L2"]
	v := input.levels[lvl][f]
	not typed(f, v)
}

violations contains violation("TYPE_MISMATCH", "RULE-TYP-001") if {
	some f in all_keys
	declared(f)
	v := input.levels.L3.values[f]
	not typed(f, v)
}

# A runtime fact (L4 posture, L5 request facts) is never stored as a configuration default at any level.
violations contains violation("RUNTIME_FACT_NOT_STORABLE", "RULE-RTF-001") if {
	some f in all_keys
	override_of(f) == "RUNTIME_FACT"
}

# NO_OVERRIDE: L2 and L3 may repeat the platform value but not change it.
violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "NO_OVERRIDE"
	l2_set(f)
	not l1_set(f)
}

violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "NO_OVERRIDE"
	l2_set(f)
	l1_set(f)
	input.levels.L2[f] != input.levels.L1[f]
}

violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "NO_OVERRIDE"
	l3_set(f)
	not l1_set(f)
}

violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "NO_OVERRIDE"
	l3_set(f)
	l1_set(f)
	input.levels.L3.values[f] != input.levels.L1[f]
}

# PLATFORM_ONLY: only the platform sets it.
violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "PLATFORM_ONLY"
	l2_set(f)
}

violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "PLATFORM_ONLY"
	l3_set(f)
}

# FI_NARROW_ONLY: the FI class may narrow; the bank may not set it.
violations contains violation("OVERRIDE_NOT_PERMITTED", "RULE-OVR-001") if {
	some f in all_keys
	override_of(f) == "FI_NARROW_ONLY"
	l3_set(f)
}

narrowing_fields := {"FI_NARROW_ONLY", "BANK_NARROW_ONLY", "BANK_WITHIN_RANGE"}

# An FI value must narrow the platform's. With no platform bound there is nothing to narrow, so any value is wider.
violations contains violation("WIDENS_INHERITED_VALUE", "RULE-OVR-002") if {
	some f in all_keys
	override_of(f) in narrowing_fields
	l2_set(f)
	typed(f, input.levels.L2[f])
	not l1_set(f)
}

violations contains violation("WIDENS_INHERITED_VALUE", "RULE-OVR-002") if {
	some f in all_keys
	override_of(f) in narrowing_fields
	l2_set(f)
	l1_set(f)
	typed(f, input.levels.L2[f])
	typed(f, input.levels.L1[f])
	not no_wider(f, input.levels.L2[f], input.levels.L1[f])
}

# The bank's value must narrow what it inherits (BANK_NARROW_ONLY and BANK_WITHIN_RANGE).
bank_bound_fields := {"BANK_NARROW_ONLY", "BANK_WITHIN_RANGE"}

violations contains violation("WIDENS_INHERITED_VALUE", "RULE-OVR-002") if {
	some f in all_keys
	override_of(f) in bank_bound_fields
	l3_set(f)
	typed(f, input.levels.L3.values[f])
	not has_bound(f)
}

violations contains violation("WIDENS_INHERITED_VALUE", "RULE-OVR-002") if {
	some f in all_keys
	override_of(f) in bank_bound_fields
	l3_set(f)
	has_bound(f)
	typed(f, input.levels.L3.values[f])
	typed(f, inherited(f))
	not no_wider(f, input.levels.L3.values[f], inherited(f))
}

# BANK_WITHIN_RANGE: the value must also sit inside the profile's range. A field with no usable range is invalid.
violations contains violation("OUT_OF_RANGE", "RULE-RNG-001") if {
	some f in all_keys
	override_of(f) == "BANK_WITHIN_RANGE"
	l3_set(f)
	typed(f, input.levels.L3.values[f])
	not range_ok(f)
}

range_ok(f) if {
	r := input.schema.fields[f].range
	v := input.levels.L3.values[f]
	is_number(r.min)
	is_number(r.max)
	v >= r.min
	v <= r.max
}

# ---- effective configuration --------------------------------------------------------------------------

effective_value(f) := [input.levels.L3.values[f], "L3"] if l3_set(f)

effective_value(f) := [input.levels.L2[f], "L2"] if {
	not l3_set(f)
	l2_set(f)
}

effective_value(f) := [input.levels.L1[f], "L1"] if {
	not l3_set(f)
	not l2_set(f)
	l1_set(f)
}

storable(f) if override_of(f) != "RUNTIME_FACT"

effective := {f: effective_value(f)[0] |
	some f in all_keys
	declared(f)
	storable(f)
}

provenance := {f: effective_value(f)[1] |
	some f in all_keys
	declared(f)
	storable(f)
}

# ---- the decision ----------------------------------------------------------------------------------

decision := {
	"valid": true,
	"reason_codes": [],
	"rule_refs": [],
	"effective": effective,
	"provenance": provenance,
} if {
	input_ok
	count(violations) == 0
}

decision := {
	"valid": false,
	"reason_codes": sort({v.reason | some v in violations}),
	"rule_refs": sort({v.rule | some v in violations}),
	"effective": {},
	"provenance": {},
} if {
	input_ok
	count(violations) > 0
}

decision := {
	"valid": false,
	"reason_codes": ["INPUT_INCOMPLETE"],
	"rule_refs": ["RULE-INP-001"],
	"effective": {},
	"provenance": {},
} if not input_ok
