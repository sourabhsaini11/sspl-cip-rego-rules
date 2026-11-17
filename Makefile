.PHONY: check test lint fmt vet mutate compat conformance vuln promote-check

## check: the pipeline gate. Exit 0 only if the rules may be signed and shipped.
check:
	go run ./cmd/rules-check

## test: the gate's own tests (each kind of defect must be caught) plus the check on the real rules.
test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofumpt -l -w .

## mutate: mutation-test every ruleset; each rule change must make its Rego tests fail (conformance/accepted-mutants.json lists reviewed equivalents)
mutate:
	go run ./cmd/rules-conformance mutate

## compat: compare adjacent versions of a profile on the corpus; a newer version may not silently loosen a decision
compat:
	go run ./cmd/rules-conformance compat

conformance: mutate compat

## vuln: no reachable vulnerability in the module's dependencies or the Go toolchain (govulncheck)
vuln:
	govulncheck ./...

## promote-check: everything a ruleset must pass before it may be signed and promoted
promote-check: check test lint conformance vuln
