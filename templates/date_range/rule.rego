# DATE_RANGE template (P1): the span between two dates may not exceed a number of days.
#
# Facts: from_date and to_date, ISO dates (YYYY-MM-DD). The limit, in whole days, is read
# from input.values[input.rule.value_key]; it is not in this file.
#
# Fail closed: a missing, mistyped, fractional or negative limit, or a reversed range,
# leaves `decision` undefined. A date that does not parse is an engine error, which the PDS
# reports as CIP-PDE-EVAL-FAILED: no decision.
package cip.pde.template.date_range

limit_days := input.values[input.rule.value_key]

valid_limit if {
	is_number(limit_days)
	limit_days == round(limit_days)
	limit_days >= 0
}

from_ns := time.parse_ns("2006-01-02", input.facts.from_date)

to_ns := time.parse_ns("2006-01-02", input.facts.to_date)

ordered if from_ns <= to_ns

latest_ns := time.add_date(from_ns, 0, 0, limit_days)

decision := {"allow": true, "reason": "RANGE_WITHIN_LIMIT"} if {
	valid_limit
	ordered
	to_ns <= latest_ns
}

decision := {
	"allow": false,
	"reason": "RANGE_OVER_LIMIT",
	"reason_code": "CIP-POL-LIMIT",
	"details": {"rule_id": input.rule.rule_id},
} if {
	valid_limit
	ordered
	to_ns > latest_ns
}
