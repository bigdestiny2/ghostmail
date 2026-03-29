VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
GOBIN := bin

.PHONY: build build-server build-ctl test clean release docker

build: build-server build-ctl

build-server:
	go build $(LDFLAGS) -o $(GOBIN)/ghostmail ./cmd/ghostmail

build-ctl:
	go build $(LDFLAGS) -o $(GOBIN)/ghostctl ./cmd/ghostctl

test:
	go test -race -count=1 ./...

clean:
	rm -rf $(GOBIN)

release:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/ghostmail-linux-amd64 ./cmd/ghostmail
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/ghostctl-linux-amd64 ./cmd/ghostctl
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/ghostmail-linux-arm64 ./cmd/ghostmail
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/ghostctl-linux-arm64 ./cmd/ghostctl
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/ghostmail-darwin-arm64 ./cmd/ghostmail
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/ghostctl-darwin-arm64 ./cmd/ghostctl

docker:
	docker build -t ghostmail:$(VERSION) .
