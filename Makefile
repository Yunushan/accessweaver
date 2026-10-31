.PHONY: build test vet fmt run check
build:
	go build -trimpath -ldflags="-s -w" -o bin/accessweaver ./cmd/accessweaver
run:
	go run ./cmd/accessweaver ui
fmt:
	gofmt -w cmd internal
vet:
	go vet ./...
test:
	go test ./... -count=1 -race
check: vet test
