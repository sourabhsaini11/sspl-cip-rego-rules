# Control plane: release_access v1 (PDE architecture document Journey 8, sections 12, 13, 24 and 33; FF-12).
#
# The Landing Zone asks, before it lets an actor act on a change: may this actor submit it, approve it, or activate it? OPA
# returns a bounded result, PERMIT or DENY: it never approves, publishes or activates anything. PERMIT means the action may be
# attempted; the Landing Zone's governance workflow records the approval and the deployment controller publishes. An actor
# never approves or activates a change they authored (no maker self-approval). Activation needs the release approver and
# PHOENIX gates, a conformance record and an approval by someone other than the author.
#
# Rules carry no data: which role may do what to which kind of change is the Landing Zone's RBAC, and arrives as
# input.permissions; the rules hold no role name. Missing or malformed input is a DENY (INPUT_INCOMPLETE): an undefined
# decision must never be read as PERMIT.
#
# Contract: docs/rules-contract.md (PDS repository), section 11.2. Provisional: the document names the journey, not the roles.
package cip.pde.control.release_access.v1

known_actions := {"SUBMIT", "APPROVE", "ACTIVATE"}

known_kinds := {"POLICY", "CONFIGURATION"}

filled(s) if {
	is_string(s)
	s != ""
}

input_ok if {
	filled(input.actor.id)
	filled(input.actor.role)
	input.action in known_actions
	filled(input.change.id)
	input.change.kind in known_kinds
	filled(input.change.author_id)
	is_array(input.change.approvals)
	is_object(input.change.gates)
	is_array(input.permissions)
}

# ---- what the actor's role may do (the table is input) ----------------------------------------------

may_do_the_action if {
	some p in input.permissions
	p.role == input.actor.role
	p.action == input.action
}

may_do_it_to_this_kind if {
	some p in input.permissions
	p.role == input.actor.role
	p.action == input.action
	p.kind == input.change.kind
}

# ---- activation gates ------------------------------------------------------------------------------

gates_complete if {
	input.change.gates.release_approver == true
	input.change.gates.phoenix == true
	is_string(input.change.gates.conformance_testpack)
	startswith(input.change.gates.conformance_testpack, "TESTPACK-")
	independent_approval
}

independent_approval if {
	some a in input.change.approvals
	a.actor_id != input.change.author_id
}

# ---- violations: each one a reason and a rule reference -----------------------------------------------

violation(reason, ref) := {"reason": reason, "rule": ref}

# An author never approves or activates their own change.
violations contains violation("SAME_ACTOR", "RULE-REL-001") if {
	input.action in {"APPROVE", "ACTIVATE"}
	input.actor.id == input.change.author_id
}

violations contains violation("ROLE_NOT_PERMITTED", "RULE-REL-002") if not may_do_the_action

violations contains violation("CHANGE_KIND_NOT_PERMITTED", "RULE-REL-004") if {
	may_do_the_action
	not may_do_it_to_this_kind
}

violations contains violation("GATES_INCOMPLETE", "RULE-REL-003") if {
	input.action == "ACTIVATE"
	not gates_complete
}

permitted_reason := {"SUBMIT": ["SUBMIT_PERMITTED", "RULE-REL-010"], "APPROVE": ["APPROVAL_PERMITTED", "RULE-REL-011"], "ACTIVATE": ["ACTIVATION_PERMITTED", "RULE-REL-012"]}

# ---- the decision -------------------------------------------------------------------------------------

decision := {
	"result": "PERMIT",
	"reason_codes": [permitted_reason[input.action][0]],
	"rule_refs": [permitted_reason[input.action][1]],
} if {
	input_ok
	count(violations) == 0
}

decision := {
	"result": "DENY",
	"reason_codes": sort({v.reason | some v in violations}),
	"rule_refs": sort({v.rule | some v in violations}),
} if {
	input_ok
	count(violations) > 0
}

decision := {
	"result": "DENY",
	"reason_codes": ["INPUT_INCOMPLETE"],
	"rule_refs": ["RULE-INP-001"],
} if not input_ok
