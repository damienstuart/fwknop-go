MODULE   := github.com/damienstuart/fwknop-go
BIN_DIR  := bin

CLIENT   := $(BIN_DIR)/fwknop
SERVER   := $(BIN_DIR)/fwknopd
CONVERT  := $(BIN_DIR)/fwknop-convert

GO       := go
GOFLAGS  ?=
LDFLAGS  ?=

.PHONY: all lib client server convert clean test retest vet fmt tidy install help

all: client server convert  ## Build all binaries

lib:  ## Build and verify the fkospa library
	$(GO) build $(GOFLAGS) ./fkospa/...

client:  ## Build the fwknop client
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CLIENT) ./cmd/fwknop

server:  ## Build the fwknopd server
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(SERVER) ./cmd/fwknopd

convert:  ## Build the fwknop-convert utility
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CONVERT) ./cmd/fwknop-convert

install:  ## Install binaries to $GOPATH/bin
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknop
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknopd
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknop-convert

test:  ## Run all tests (may use cache)
	$(GO) test ./...

retest:  ## Run all tests (no cache)
	$(GO) test -count=1 ./...

vet:  ## Run go vet
	$(GO) vet ./...

fmt:  ## Run gofmt on all Go files
	gofmt -s -w .

tidy:  ## Tidy module dependencies
	$(GO) mod tidy

clean:  ## Remove build artifacts
	rm -rf $(BIN_DIR)

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
