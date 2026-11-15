# Whois2Api — developer entry points. Run `make help` for the list.
BINARY      := whois2api
PKG         := github.com/asoe/whois2api
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(BUILD_DATE)
GO          ?= go

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/whois2api

.PHONY: run
run: ## Run from source on :8080
	$(GO) run ./cmd/whois2api

.PHONY: test
test: ## Run the test suite
	$(GO) test ./...

.PHONY: race
race: ## Run tests with the race detector (needs a C compiler)
	CGO_ENABLED=1 $(GO) test -race ./...

.PHONY: cover
cover: ## Show coverage per package
	$(GO) test -cover ./...

.PHONY: lint
lint: ## Vet and check formatting
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "unformatted files above" && exit 1)

.PHONY: fmt
fmt: ## Format all Go sources
	gofmt -w .

.PHONY: assets
assets: ## Re-encode the PNG logos from web/logo.svg
	@command -v python3 >/dev/null || (echo "python3 required"; exit 1)
	python3 -c "import cairosvg" 2>/dev/null || pip install --quiet cairosvg
	python3 scripts/render_logos.py
	cp web/index.html web/app.css web/app.js web/i18n.js web/logo.svg \
	   web/logo-180.png web/logo-512.png web/favicon-32.png internal/api/assets/

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist

# --- Docker -----------------------------------------------------------------

IMAGE ?= whois2api:dev
.PHONY: docker
docker: ## Build the container image
	docker build -t $(IMAGE) .

.PHONY: docker-run
docker-run: ## Run the container with a persistent data volume
	docker run --rm -p 8080:8080 -v whois2api-data:/data $(IMAGE)

.PHONY: smoke
smoke: build ## Start the binary and probe the main endpoints
	./scripts/smoke.sh
