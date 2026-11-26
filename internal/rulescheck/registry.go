package rulescheck

import (
	"path/filepath"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

func (c *checker) loadRegistry() {
	raw, err := safefs.ReadFile(filepath.Join(c.root, reasonsRel))
	if err != nil {
		c.add(reasonsRel, "cannot read the reason registry: %v", err)
		return
	}
	var r registry
	if err := decodeStrict(raw, &r); err != nil {
		c.add(reasonsRel, "not a valid reason registry: %v", err)
		return
	}
	c.reg = &r
	for _, s := range r.ReservedForPDS {
		c.reserved[s] = true
	}
	for _, s := range r.AllowedReasonCodes {
		c.codes[s] = true
	}
	if len(c.codes) == 0 {
		c.add(reasonsRel, "allowed_reason_codes is empty")
	}
	seen := map[string]bool{}
	for _, e := range r.Reasons {
		who := e.Profile + "/" + e.Reason
		switch {
		case !profileRe.MatchString(e.Profile):
			c.add(reasonsRel, "%s: profile is not a valid profile name", who)
		case !reasonRe.MatchString(e.Reason):
			c.add(reasonsRel, "%s: reason must be UPPER_SNAKE_CASE", who)
		case c.reserved[e.Reason]:
			c.add(reasonsRel, "%s: reason is reserved for the PDS and cannot be registered for rules", who)
		}
		if seen[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seen[who] = true
		c.checkVerdict(who, e.Verdict, e.ReasonCode)
	}
	seenLit := map[string]bool{}
	for _, e := range r.Literals {
		who := "literal " + e.Profile + "/" + e.Literal
		switch {
		case !profileRe.MatchString(e.Profile):
			c.add(reasonsRel, "%s: profile is not a valid profile name", who)
		case !reasonRe.MatchString(e.Literal):
			c.add(reasonsRel, "%s: literal must be UPPER_SNAKE_CASE", who)
		case !literalKinds[e.Kind]:
			c.add(reasonsRel, "%s: kind must be OPERATION, OBLIGATION or POSTURE, got %q", who, e.Kind)
		case c.reserved[e.Literal] || results[e.Literal]:
			c.add(reasonsRel, "%s: a reserved reason or a result cannot be a literal", who)
		}
		if seenLit[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seenLit[who] = true
		for _, rr := range r.Reasons {
			if rr.Profile == e.Profile && rr.Reason == e.Literal {
				c.add(reasonsRel, "%s: is also registered as a reason; it is one or the other", who)
			}
		}
	}
	seenTpl := map[string]bool{}
	for _, e := range r.TemplateReasons {
		who := "template " + e.RuleType + "/" + e.Reason
		switch {
		case !ruleTypeRe.MatchString(e.RuleType):
			c.add(reasonsRel, "%s: rule_type must be UPPER_SNAKE_CASE", who)
		case !reasonRe.MatchString(e.Reason):
			c.add(reasonsRel, "%s: reason must be UPPER_SNAKE_CASE", who)
		case c.reserved[e.Reason]:
			c.add(reasonsRel, "%s: reason is reserved for the PDS and cannot be registered for rules", who)
		}
		if seenTpl[who] {
			c.add(reasonsRel, "%s: duplicate entry", who)
		}
		seenTpl[who] = true
		c.checkVerdict(who, e.Verdict, e.ReasonCode)
	}
}

// results are the seven results of the PDE architecture document (section 8). A v2 ruleset
// returns one as a string, so the reason scan must not mistake it for a reason.
var results = map[string]bool{
	"PERMIT": true, "DENY": true, "STEP_UP": true, "NEED_EVIDENCE": true,
	"REFER": true, "DEFER_UNAVAILABLE": true, "INDETERMINATE": true,
}

// checkVerdict validates a registered reason's verdict and class. The verdict is one of the
// seven results, or ALLOW or REJECT for a contract v1 ruleset. Only a permit (PERMIT, ALLOW)
// carries no reason_code; every other verdict needs one of the four platform classes.
func (c *checker) checkVerdict(who, verdict, code string) {
	switch {
	case verdict == "ALLOW" || verdict == "PERMIT":
		if code != "" {
			c.add(reasonsRel, "%s: a %s reason carries no reason_code, got %q", who, verdict, code)
		}
	case verdict == "REJECT" || results[verdict]:
		if !c.codes[code] {
			c.add(reasonsRel, "%s: a %s reason needs a reason_code from allowed_reason_codes, got %q", who, verdict, code)
		}
	default:
		c.add(reasonsRel, "%s: verdict must be one of the seven results, or ALLOW or REJECT, got %q", who, verdict)
	}
}
