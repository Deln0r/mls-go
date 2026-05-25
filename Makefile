.PHONY: test smoketest vet fmt all

# Run every package's tests with the race detector and a fresh cache.
test:
	go test -race -count=1 ./...

# Run the 3-member end-to-end smoke flow exercised by CI.
smoketest:
	go run ./cmd/mls-smoketest

# Static analysis.
vet:
	go vet ./...

# Format every Go file in place.
fmt:
	gofmt -s -w .

# Convenience: everything CI runs on every push.
all: fmt vet test smoketest
