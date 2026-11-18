package cip.pde.control.release_access.v1_test

import data.cip.pde.control.release_access.v1 as ra

# Journey 8 (document section 24): a policy engineer proposes POL-KGB001-UPI-v6 while a bank Product Officer separately
# proposes CFG-KGB001-UPI-v3. The author may submit a draft only; the same actor approving their own change is DENY
# SAME_ACTOR; a tested, signed bundle may be activated only with the release approver and PHOENIX gates complete. OPA never
# approves or activates anything: PERMIT here means the action may be attempted. The role-to-permission table is the Landing
# Zone's RBAC data and arrives in the input (rules carry no data).
permissions := [
	{"role": "POLICY_AUTHOR", "action": "SUBMIT", "kind": "POLICY"},
	{"role": "PRODUCT_OFFICER", "action": "SUBMIT", "kind": "CONFIGURATION"},
	{"role": "POLICY_CHECKER", "action": "APPROVE", "kind": "POLICY"},
	{"role": "BANK_CHECKER", "action": "APPROVE", "kind": "CONFIGURATION"},
	{"role": "RELEASE_CONTROLLER", "action": "ACTIVATE", "kind": "POLICY"},
	{"role": "RELEASE_CONTROLLER", "action": "ACTIVATE", "kind": "CONFIGURATION"},
]

change := {
	"id": "CHG-POL-KGB001-UPI-v6", "kind": "POLICY", "author_id": "ENG-022",
	"approvals": [{"actor_id": "ENG-031", "role": "POLICY_CHECKER"}],
	"gates": {"release_approver": true, "phoenix": true, "conformance_testpack": "TESTPACK-UPI-v6-PASS"},
}

base := {
	"ctx": {"now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"actor": {"id": "ENG-022", "role": "POLICY_AUTHOR"},
	"action": "SUBMIT",
	"change": change,
	"permissions": permissions,
}

acting(actor, action) := object.union(base, {"actor": actor, "action": action})

activation(gates) := json.patch(acting({"id": "DEP-1", "role": "RELEASE_CONTROLLER"}, "ACTIVATE"), [{"op": "replace", "path": "/change/gates", "value": gates}])

full_gates := {"release_approver": true, "phoenix": true, "conformance_testpack": "TESTPACK-UPI-v6-PASS"}

reasons(d) := {r | some r in d.reason_codes}

refs(d) := {r | some r in d.rule_refs}

test_the_author_may_submit_a_draft if {
	d := ra.decision with input as base
	d.result == "PERMIT"
	reasons(d) == {"SUBMIT_PERMITTED"}
	refs(d) == {"RULE-REL-010"}
}

test_a_product_officer_may_submit_a_configuration_change if {
	v := json.patch(acting({"id": "BNK-7", "role": "PRODUCT_OFFICER"}, "SUBMIT"), [{"op": "replace", "path": "/change/kind", "value": "CONFIGURATION"}, {"op": "replace", "path": "/change/author_id", "value": "BNK-7"}])
	d := ra.decision with input as v
	d.result == "PERMIT"
}

test_the_same_actor_approving_their_own_change_is_denied if {
	d := ra.decision with input as acting({"id": "ENG-022", "role": "POLICY_CHECKER"}, "APPROVE")
	d.result == "DENY"
	reasons(d) == {"SAME_ACTOR"}
	refs(d) == {"RULE-REL-001"}
}

test_an_independent_checker_may_approve if {
	d := ra.decision with input as acting({"id": "ENG-031", "role": "POLICY_CHECKER"}, "APPROVE")
	d.result == "PERMIT"
	reasons(d) == {"APPROVAL_PERMITTED"}
	refs(d) == {"RULE-REL-011"}
}

test_the_author_may_not_activate_their_own_change if {
	v := object.union(activation(full_gates), {"actor": {"id": "ENG-022"}})
	d := ra.decision with input as v
	d.result == "DENY"
	reasons(d) == {"SAME_ACTOR"}
}

test_a_tested_signed_bundle_with_every_gate_may_be_activated if {
	d := ra.decision with input as activation(full_gates)
	d.result == "PERMIT"
	reasons(d) == {"ACTIVATION_PERMITTED"}
	refs(d) == {"RULE-REL-012"}
}

test_each_missing_gate_blocks_activation if {
	every gates in [
		object.union(full_gates, {"release_approver": false}),
		object.union(full_gates, {"phoenix": false}),
		object.union(full_gates, {"conformance_testpack": ""}),
		object.union(full_gates, {"conformance_testpack": "SOMETHING-ELSE"}),
		object.union(full_gates, {"conformance_testpack": 5}),
	] {
		d := ra.decision with input as activation(gates)
		d.result == "DENY"
		reasons(d) == {"GATES_INCOMPLETE"}
		refs(d) == {"RULE-REL-003"}
	}
}

test_a_missing_gate_key_blocks_activation if {
	every part in ["release_approver", "phoenix", "conformance_testpack"] {
		d := ra.decision with input as activation(json.remove(full_gates, [part]))
		reasons(d) == {"GATES_INCOMPLETE"}
	}
}

test_activation_needs_an_approval_by_someone_other_than_the_author if {
	none := json.patch(activation(full_gates), [{"op": "replace", "path": "/change/approvals", "value": []}])
	reasons(ra.decision) == {"GATES_INCOMPLETE"} with input as none
	own := json.patch(activation(full_gates), [{"op": "replace", "path": "/change/approvals", "value": [{"actor_id": "ENG-022", "role": "POLICY_CHECKER"}]}])
	reasons(ra.decision) == {"GATES_INCOMPLETE"} with input as own
}

test_a_role_with_no_permission_for_the_action_is_denied if {
	d := ra.decision with input as acting({"id": "ENG-099", "role": "POLICY_AUTHOR"}, "APPROVE")
	d.result == "DENY"
	reasons(d) == {"ROLE_NOT_PERMITTED"}
	refs(d) == {"RULE-REL-002"}
}

test_a_role_that_may_act_but_not_on_this_kind_of_change_is_denied if {
	v := json.patch(base, [{"op": "replace", "path": "/change/kind", "value": "CONFIGURATION"}])
	d := ra.decision with input as v
	d.result == "DENY"
	reasons(d) == {"CHANGE_KIND_NOT_PERMITTED"}
	refs(d) == {"RULE-REL-004"}
}

test_an_unknown_role_is_denied if {
	d := ra.decision with input as acting({"id": "X-1", "role": "SUPERUSER"}, "SUBMIT")
	reasons(d) == {"ROLE_NOT_PERMITTED"}
}

test_the_permission_table_is_data_not_rules if {
	# With no permissions published nobody may do anything: the rules hold no role names.
	d := ra.decision with input as json.patch(base, [{"op": "replace", "path": "/permissions", "value": []}])
	d.result == "DENY"
	reasons(d) == {"ROLE_NOT_PERMITTED"}
}

test_every_failure_is_reported if {
	v := json.patch(activation(object.union(full_gates, {"phoenix": false})), [{"op": "replace", "path": "/actor", "value": {"id": "ENG-022", "role": "POLICY_AUTHOR"}}])
	d := ra.decision with input as v
	reasons(d) == {"SAME_ACTOR", "ROLE_NOT_PERMITTED", "GATES_INCOMPLETE"}
}

test_missing_input_is_a_deny_never_a_permit if {
	every part in ["actor/id", "actor/role", "action", "change/id", "change/kind", "change/author_id", "change/approvals", "change/gates", "permissions"] {
		d := ra.decision with input as json.remove(base, [part])
		d.result == "DENY"
		reasons(d) == {"INPUT_INCOMPLETE"}
		refs(d) == {"RULE-INP-001"}
	}
}

test_an_unknown_action_or_change_kind_is_incomplete if {
	reasons(ra.decision) == {"INPUT_INCOMPLETE"} with input as object.union(base, {"action": "DELETE"})
	reasons(ra.decision) == {"INPUT_INCOMPLETE"} with input as json.patch(base, [{"op": "replace", "path": "/change/kind", "value": "BUNDLE"}])
}

test_an_empty_input_is_a_deny if {
	d := ra.decision with input as {}
	d.result == "DENY"
	reasons(d) == {"INPUT_INCOMPLETE"}
}

test_the_output_carries_only_the_closed_keys_and_never_an_approval if {
	d := ra.decision with input as base
	{k | some k, _ in d} == {"result", "reason_codes", "rule_refs"}
}

test_submitting_is_not_blocked_by_being_the_author if {
	# Only approving or activating your own change is a breach; submitting is the author's job.
	ra.decision.result == "PERMIT" with input as base
}
