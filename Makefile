.PHONY: build test test-verbose test-integration test-coverage lint clean run docker mockupf

BINARY=pfcp-generator
VERSION=1.0.0

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/pfcp-generator/

test:
	go test ./internal/... ./pkg/...

test-verbose:
	go test -v ./internal/... ./pkg/...

test-integration:
	go test -v -tags=integration ./test/integration/...

test-coverage:
	go test -coverprofile=coverage.out ./internal/... ./pkg/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

mockupf:
	go build -o mockupf ./test/mockupf/

docker:
	docker build -t pfcp-generator .

clean:
	rm -f $(BINARY) mockupf coverage.out coverage.html

run: build
	./$(BINARY) --config config.yaml
