package rulescheck

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"unicode"
)

// The approved text for GET_SAFE_REASON (PDE architecture document, section 9) is policy data: this file ships to the PDS as the
// "safe_reasons" document (rules-gen -policy-data). The PDS refuses a catalogue with an unapproved entry when it loads it; this
// check refuses it before it is signed, and goes further, because only the rules repository knows which reasons exist: an entry
// must be for a reason a ruleset can return, or one the PDS owns. The format is the PDS's (docs/rules-contract.md, section 4.4b).

const (
	safeReasonsRel    = "policy-data/safe-reasons.json"
	safeReasonsFormat = "pde-safe-reasons/v1"
	safeReasonsMaxLen = 400
)

var (
	safeRefRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{2,63}$`)
	safeLeakRe = regexp.MustCompile(`input\.|data\.|package |[<>{}]|:=|==`)
)

type safeReasonsDoc struct {
	Format  string            `json:"format"`
	Entries []safeReasonEntry `json:"entries"`
}

type safeReasonEntry struct {
	Profile     string `json:"profile"`
	Reason      string `json:"reason"`
	Text        string `json:"text"`
	AppealRef   string `json:"appeal_ref"`
	ApprovalRef string `json:"approval_ref"`
}

// checkSafeReasons validates the catalogue when there is one. No file is a valid state: the PDS then answers with the text per result.
func (c *checker) checkSafeReasons() {
	raw, err := os.ReadFile(filepath.Join(c.root, safeReasonsRel))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.add(safeReasonsRel, "cannot read the safe-reason catalogue: %v", err)
		return
	}
	var d safeReasonsDoc
	if err := decodeStrict(raw, &d); err != nil {
		c.add(safeReasonsRel, "safe-reasons: not a valid catalogue: %v", err)
		return
	}
	if d.Format != safeReasonsFormat {
		c.add(safeReasonsRel, "safe-reasons: format must be %q", safeReasonsFormat)
	}
	registered := map[string]bool{} // "profile/reason"
	anyProfile := map[string]bool{} // reason registered for some profile
	if c.reg != nil {
		for _, r := range c.reg.Reasons {
			registered[r.Profile+"/"+r.Reason] = true
			anyProfile[r.Reason] = true
		}
		for _, r := range c.reg.TemplateReasons { // a template runs for every profile it is bound to
			anyProfile[r.Reason] = true
		}
	}
	seen := map[string]bool{}
	for i, e := range d.Entries {
		who := "safe-reasons entry " + e.Profile + "/" + e.Reason
		if e.Reason == "" {
			who = "safe-reasons entry " + strconv.Itoa(i+1)
		}
		switch {
		case !reasonRe.MatchString(e.Reason):
			c.add(safeReasonsRel, "%s: reason must be UPPER_SNAKE_CASE", who)
		case e.Profile != "" && !profileRe.MatchString(e.Profile):
			c.add(safeReasonsRel, "%s: profile is not a valid profile name", who)
		case c.reserved[e.Reason]:
			// a reason the PDS itself returns: approved text may be written for it
		case e.Profile != "" && !registered[e.Profile+"/"+e.Reason] && !tplReason(c, e.Reason):
			c.add(safeReasonsRel, "%s: %s is not a registered reason of %s, so no ruleset can return it", who, e.Reason, e.Profile)
		case e.Profile == "" && !anyProfile[e.Reason]:
			c.add(safeReasonsRel, "%s: %s is not a registered reason of any profile and not one the PDS owns", who, e.Reason)
		}
		switch {
		case e.Text == "":
			c.add(safeReasonsRel, "%s: text is required", who)
		case len(e.Text) > safeReasonsMaxLen:
			c.add(safeReasonsRel, "%s: text is longer than %d bytes", who, safeReasonsMaxLen)
		case safeLeakRe.MatchString(e.Text):
			c.add(safeReasonsRel, "%s: text carries a rule, a path or markup", who)
		case hasControlRune(e.Text):
			c.add(safeReasonsRel, "%s: text carries a control character", who)
		}
		if !safeRefRe.MatchString(e.AppealRef) {
			c.add(safeReasonsRel, "%s: appeal_ref is required and must look like APPEAL-UPI-01", who)
		}
		if !safeRefRe.MatchString(e.ApprovalRef) {
			c.add(safeReasonsRel, "%s: approval_ref is required: text nobody approved is refused", who)
		}
		k := e.Profile + "/" + e.Reason
		if seen[k] {
			c.add(safeReasonsRel, "%s: given twice", who)
		}
		seen[k] = true
	}
}

func hasControlRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func tplReason(c *checker, reason string) bool {
	if c.reg == nil {
		return false
	}
	for _, r := range c.reg.TemplateReasons {
		if r.Reason == reason {
			return true
		}
	}
	return false
}
