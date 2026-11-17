.PHONY: check test lint fmt vet

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
