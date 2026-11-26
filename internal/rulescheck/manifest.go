package rulescheck

import (
	"os"
	"path/filepath"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

func (c *checker) loadManifest() *manifest {
	raw, err := safefs.ReadFile(filepath.Join(c.root, manifestRel))
	if err != nil {
		c.add(manifestRel, "cannot read the manifest: %v", err)
		return nil
	}
	var m manifest
	if err := decodeStrict(raw, &m); err != nil {
		c.add(manifestRel, "not a valid manifest: %v", err)
		return nil
	}
	return &m
}

func (c *checker) checkManifest(m *manifest) {
	if m.BundleID == "" {
		c.add(manifestRel, "bundle_id is empty")
	}
	if !revisionRe.MatchString(m.Revision) {
		c.add(manifestRel, "revision %q is not yyyy.mm.dd-n", m.Revision)
	}
	if m.InputContract != SupportedInputContract {
		c.add(manifestRel, "input_contract %q is not the contract the PDS builds (%s): the PDS would refuse this bundle",
			m.InputContract, SupportedInputContract)
	}
	if m.GitCommit != "" && !commitRe.MatchString(m.GitCommit) {
		c.add(manifestRel, "git_commit %q is not a 40-character commit id", m.GitCommit)
	}
	if len(m.Rulesets) == 0 {
		c.add(manifestRel, "no rulesets")
	}
	paths, versions := map[string]bool{}, map[string]bool{}
	for _, e := range m.Rulesets {
		who := e.Profile + "@" + e.Version
		if !profileRe.MatchString(e.Profile) {
			c.add(manifestRel, "%s: profile is not a valid profile name", who)
		}
		if !versionRe.MatchString(e.Version) {
			c.add(manifestRel, "%s: version must look like v5", who)
		}
		if want := packageFor(e.Profile, e.Version); e.Package != want {
			c.add(manifestRel, "%s: package %q must be %q", who, e.Package, want)
		}
		if e.Path == "" || !filepath.IsLocal(e.Path) {
			c.add(manifestRel, "%s: path %q must be a relative path inside rulesets/", who, e.Path)
		}
		if e.CompatibleSince != "" && !versionRe.MatchString(e.CompatibleSince) {
			c.add(manifestRel, "%s: compatible_since %q must look like v4", who, e.CompatibleSince)
		}
		switch {
		case e.RiskClass == "":
			c.add(manifestRel, "%s: risk_class is required (CONSEQUENTIAL, STANDARD or LOW_RISK)", who)
		case !riskClasses[e.RiskClass]:
			c.add(manifestRel, "%s: risk_class %q must be CONSEQUENTIAL, STANDARD or LOW_RISK", who, e.RiskClass)
		}
		if paths[e.Path] {
			c.add(manifestRel, "%s: path %q is used by two rulesets", who, e.Path)
		}
		if versions[who] {
			c.add(manifestRel, "%s: listed twice", who)
		}
		paths[e.Path], versions[who] = true, true
	}
	c.checkTenancy(m)
	// Every version of a profile carries one class: an older version stays loadable, so a class that moves
	// on the newest version alone would let a request ask for the older, lower-classed one.
	byProfile := map[string]string{}
	reported := map[string]bool{}
	for _, e := range m.Rulesets {
		if e.RiskClass == "" || !riskClasses[e.RiskClass] {
			continue
		}
		if first, seen := byProfile[e.Profile]; !seen {
			byProfile[e.Profile] = e.RiskClass
		} else if first != e.RiskClass && !reported[e.Profile] {
			reported[e.Profile] = true
			c.add(manifestRel, "%s: risk_class differs between versions (%s and %s); every version of a profile must carry the same class", e.Profile, first, e.RiskClass)
		}
	}
}

// checkOrphans finds ruleset directories that exist on disk but are not in the manifest: they
// would never be signed, so nobody would notice they were not shipping.
func (c *checker) checkOrphans(m *manifest) {
	listed := map[string]bool{}
	for _, e := range m.Rulesets {
		listed[filepath.ToSlash(filepath.Clean(e.Path))] = true
	}
	base := filepath.Join(c.root, "rulesets")
	profiles, err := os.ReadDir(base)
	if err != nil {
		return // loadManifest already reported an unreadable rulesets directory
	}
	for _, p := range profiles {
		if !p.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(base, p.Name()))
		if err != nil {
			continue
		}
		for _, v := range versions {
			rel := p.Name() + "/" + v.Name()
			if v.IsDir() && !listed[rel] {
				c.add("rulesets/"+rel, "ruleset directory is not in the manifest, so it would never ship")
			}
		}
	}
}
