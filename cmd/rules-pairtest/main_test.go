package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAPassingPairWritesItsTestpackRecord(t *testing.T) {
	out := filepath.Join(t.TempDir(), "testpack.json")

	code, stdout, stderr := exec(t, "-root", "../..", "-spec", "../../conformance/pairs/bridge_upi_v7.json", "-out", out)

	require.Equal(t, 0, code, stderr)
	require.Regexp(t, `TESTPACK-UPI-v7-[0-9a-f]{8}-PASS`, stdout)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(raw, &rec))
	require.Equal(t, "PASS", rec["status"])
}

func TestAFailingPairExitsNonZeroAndWritesNothing(t *testing.T) {
	spec := filepath.Join(t.TempDir(), "spec.json")
	raw, err := os.ReadFile("../../conformance/pairs/bridge_upi_v7.json")
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["runtime"].([]any)[0].(map[string]any)["want_result"] = "PERMIT"
	b, _ := json.Marshal(m)
	require.NoError(t, os.WriteFile(spec, b, 0o600))
	out := filepath.Join(t.TempDir(), "testpack.json")

	code, _, stderr := exec(t, "-root", "../..", "-spec", spec, "-out", out)

	require.Equal(t, 1, code)
	require.Contains(t, stderr, "GUARDED")
	require.NoFileExists(t, out)
}

func TestMissingFlagsAreUsageErrors(t *testing.T) {
	code, _, _ := exec(t)
	require.Equal(t, 2, code)
	code, _, _ = exec(t, "-spec", "x")
	require.Equal(t, 2, code)
}
