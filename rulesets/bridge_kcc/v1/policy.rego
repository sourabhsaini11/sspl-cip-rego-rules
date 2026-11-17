# BRIDGE-KCC ruleset v1 - Kisan Credit Card evidence prerequisites (PDE architecture document,
# journey 5).
#
# Operation: KCC_ASSESS. Any other operation leaves `decision` undefined (RULE_UNDEFINED).
#
# This ruleset never sanctions and never disburses: it says whether the evidence prerequisites hold.
# Conflicting evidence is a REFER, not an automatic decision: the land document and the cultivation
# record may differ by at most input.values.kcc_area_tolerance_milli_acres; beyond that the answer is
# REFER with LAND_EVIDENCE_MISMATCH and the obligation CERTIFIED_SOURCE_REQUIRED, so the loan officer
# obtains a corrected certified source and resubmits. Evidence with no source reference is
# NEED_EVIDENCE: nothing is judged on an anonymous source. Areas are whole thousandths of an acre.
# The evidence is never rewritten here.
#
# Fail closed: a missing or mistyped tolerance leaves `decision` undefined. Input contract: v1.
package cip.pde.bridge_kcc.v1

whole_number(x) if {
	is_number(x)
	x == round(x)
}

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.kcc_area_tolerance_milli_acres)
}

has_source if input.facts.source_ref

difference := abs(input.facts.land_document_area_milli_acres - input.facts.cultivation_area_milli_acres)

consistent if difference <= input.values.kcc_area_tolerance_milli_acres

decision := {
	"result": "NEED_EVIDENCE",
	"reason": "SOURCE_REF_REQUIRED",
	"reason_code": "CIP-POL-DENY",
	"obligation_refs": ["PROVIDE_SOURCE_REF"],
} if {
	input.ctx.operation == "KCC_ASSESS"
	not has_source
}

decision := {
	"result": "REFER",
	"reason": "LAND_EVIDENCE_MISMATCH",
	"reason_code": "CIP-POL-DENY",
	"obligation_refs": ["CERTIFIED_SOURCE_REQUIRED"],
	"details": {"difference_milli_acres": difference},
} if {
	input.ctx.operation == "KCC_ASSESS"
	limits_ok
	has_source
	not consistent
}

decision := {
	"result": "PERMIT",
	"reason": "EVIDENCE_CONSISTENT",
} if {
	input.ctx.operation == "KCC_ASSESS"
	limits_ok
	has_source
	consistent
}
