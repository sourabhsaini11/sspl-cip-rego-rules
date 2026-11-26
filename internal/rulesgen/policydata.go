package rulesgen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sspl/sspl-cip-rego-rules/internal/safefs"
)

// policyDataManifest is policy-data.manifest.template.json: the unsigned list of the binding files and their digests.
// The signing step stamps the revision and the MAC, as it does for the bundle; the revision moves with the
// configuration, not with the rules.
type policyDataManifest struct {
	Format        string              `json:"format"`
	BundleID      string              `json:"bundle_id"`
	InputContract string              `json:"input_contract"`
	Bindings      []policyDataBinding `json:"bindings"`
	// Documents are the permitted policy-data documents: today the approved safe-reason text (policy-data/safe-reasons.json).
	Documents []policyDataDocument `json:"documents,omitempty"`
}

type policyDataDocument struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

const (
	safeReasonsSource = "policy-data/safe-reasons.json"
	safeReasonsName   = "safe_reasons"
	safeReasonsPath   = "documents/safe_reasons.json"
)

type policyDataBinding struct {
	Profile string `json:"profile"`
	Version string `json:"version"`
	Path    string `json:"path"`
	Digest  string `json:"digest"`
}

// splitPolicyData moves the binding files and their manifest entries out of the bundle's files and manifest into a
// policy-data artefact, and returns that artefact's files.
func splitPolicyData(m *manifestFile, files map[string][]byte) (map[string][]byte, error) {
	pd := policyDataManifest{Format: "pde-policy-data/v1", BundleID: "pde-policy-data", InputContract: m.InputContract, Bindings: []policyDataBinding{}}
	out := map[string][]byte{}
	for _, b := range m.Bindings {
		raw, ok := files[b.Path]
		if !ok {
			return nil, fmt.Errorf("rulesgen: bindings file %s was not staged", b.Path)
		}
		sum := sha256.Sum256(raw)
		pd.Bindings = append(pd.Bindings, policyDataBinding{Profile: b.Profile, Version: b.Version, Path: b.Path, Digest: "sha256:" + hex.EncodeToString(sum[:])})
		out[b.Path] = raw
		delete(files, b.Path)
	}
	m.Bindings = nil
	mb, err := marshal(pd)
	if err != nil {
		return nil, err
	}
	out["policy-data.manifest.template.json"] = mb
	return out, nil
}

func sameDir(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	return errA == nil && errB == nil && aa == bb
}

// addSafeReasons ships the approved safe-reason text, when the repository has any, as a policy-data document. The file is copied
// byte for byte (the gate has already vetted it, and the PDS vets it again at load) and listed with its digest in the unsigned
// policy-data manifest. Text is configuration: it never goes into the rule bundle, so a wording change moves the policy data only.
func addSafeReasons(root string, policyFiles map[string][]byte) error {
	raw, err := safefs.ReadFile(filepath.Join(root, filepath.FromSlash(safeReasonsSource)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("rulesgen: read %s: %w", safeReasonsSource, err)
	}
	var pd policyDataManifest
	if err := json.Unmarshal(policyFiles["policy-data.manifest.template.json"], &pd); err != nil {
		return fmt.Errorf("rulesgen: policy-data manifest: %w", err)
	}
	sum := sha256.Sum256(raw)
	pd.Documents = append(pd.Documents, policyDataDocument{Name: safeReasonsName, Path: safeReasonsPath, Digest: "sha256:" + hex.EncodeToString(sum[:])})
	mb, err := marshal(pd)
	if err != nil {
		return err
	}
	policyFiles[safeReasonsPath] = raw
	policyFiles["policy-data.manifest.template.json"] = mb
	return nil
}
