GOLANG_VERSION 		?= $(shell cat .tool-versions | grep golang | cut -d' ' -f2)
VERSION 			?= $(shell go tool svu current)
REGISTRY 			?= twingate
IMAGE				:= kubernetes-gateway
IMAGE_NAME			:= $(REGISTRY)/$(IMAGE)
DOCKER_BUILDX_BUILDER ?= twingate-kubernetes-gateway-builder
DOCKER_BUILDX_CACHE ?=

export DOCKER_CLI_EXPERIMENTAL=enabled

HELP_FUN = \
    %help; \
    while(<>) { push @{$$help{$$2 // 'options'}}, [$$1, $$3] if /^([a-zA-Z\-_]+)\s*:.*\#\#(?:@([a-zA-Z\-]+))?\s(.*)$$/ }; \
    print "usage: make [target]\n\n"; \
    print "${WHITE}Variables:${RESET}\n"; \
    print "  ${YELLOW}GOLANG_VERSION${RESET} = ${GREEN}$(GOLANG_VERSION)${RESET}\n"; \
    print "  ${YELLOW}VERSION${RESET}        = ${GREEN}$(VERSION)${RESET}\n"; \
    print "  ${YELLOW}IMAGE_NAME${RESET}     = ${GREEN}$(IMAGE_NAME)${RESET}\n"; \
	print "\n"; \
    for (sort keys %help) { \
    print "${WHITE}$$_:${RESET}\n"; \
    for (@{$$help{$$_}}) { \
    $$sep = " " x (32 - length $$_->[0]); \
    print "  ${YELLOW}$$_->[0]${RESET}$$sep${GREEN}$$_->[1]${RESET}\n"; \
    }; \
    print "\n"; }

COVPROFILE_UNIT := covprofile-unit
COVPROFILE_INTEGRATION := covprofile-integration
COVERED_PACKAGES := ./cmd/...,./internal/...
UNIT_TEST_PACKAGES := ./cmd/... ./internal/...
INTEGRATION_TEST_PACKAGES := ./test/integration/...
E2E_TEST_PACKAGES := ./test/e2e/...

.PHONY: help
help: ##@other Show this help
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

.PHONY: version
version: ##@other Show the version
	@echo $(VERSION)

.PHONY: lint
lint: ##@lint Lint Go code
	@echo "Running Linter..."
	golangci-lint run --fix ./...

.PHONY: lint-dockerfile
lint-dockerfile: ##@lint Lint Dockerfile
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser-debug

.PHONY: test-helm
test-helm: ##@test Run helm-unittest
	@echo "Running Helm unit tests..."
	helm unittest deploy/gateway

.PHONY: test-helm-and-update-snapshots
test-helm-and-update-snapshots: ##@test Run helm-unittest and update the test snapshots
	@echo "Running Helm unit tests and update test snapshots..."
	helm unittest deploy/gateway -u

.PHONY: test
test: ##@test Run unit tests
	@echo "Running unit tests..."
	go test -race -v $(UNIT_TEST_PACKAGES)

.PHONY: test-with-coverage
test-with-coverage: ##@test Run unit tests with coverage
	@echo "Running unit tests with coverage..."
	go test -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)"	 -coverprofile=$(COVPROFILE_UNIT) $(UNIT_TEST_PACKAGES)

.PHONY: test-integration
test-integration: ##@test Run integration tests
	@echo "Running integration tests..."
	go test -race -v $(INTEGRATION_TEST_PACKAGES)

.PHONY: test-integration-with-coverage
test-integration-with-coverage: ##@test Run integration tests with coverage
	@echo "Running integration tests with coverage..."
	go test -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)" -coverprofile=$(COVPROFILE_INTEGRATION) $(INTEGRATION_TEST_PACKAGES)

.PHONY: test-e2e
test-e2e: ##@test Run e2e tests
	@echo "Running e2e tests..."
	go test -race -v $(E2E_TEST_PACKAGES)

.PHONY: coverall
coverall: ##@test Send code coverage to Coveralls
	@echo "Sending coverage to Coveralls..."
	go install github.com/mattn/goveralls@latest
	goveralls -coverprofile="$(COVPROFILE_UNIT),$(COVPROFILE_INTEGRATION)" -service=github


.PHONY: prepare-buildx
prepare-buildx: ##@build Prepare buildx
	@echo "Preparing buildx..."
	docker buildx create --use --name $(DOCKER_BUILDX_BUILDER) --node=$(DOCKER_BUILDX_BUILDER)

.PHONY: build
build: prepare-buildx ##@build Build the Go binaries and container images
	DOCKER_BUILDX_BUILDER=$(DOCKER_BUILDX_BUILDER) GOLANG_VERSION=$(GOLANG_VERSION) IMAGE_REGISTRY=$(REGISTRY) goreleaser release --snapshot --clean

.PHONY: cut-release-prod
cut-release-prod: ##@release Cut a production release (create a version tag and push it)
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "❌ Error: cut-release-prod can only be run on master branch. Current branch: $$(git rev-parse --abbrev-ref HEAD)"; \
		exit 1; \
	fi
	echo "🚀 Cutting a new production release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next)"
	git push --tags

.PHONY: cut-release-dev
cut-release-dev: ##@release Cut a development pre-release (create a version tag and push it)
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "❌ Error: cut-release-dev can only be run on master branch. Current branch: $$(git rev-parse --abbrev-ref HEAD)"; \
		exit 1; \
	fi
	echo "🚀 Cutting a new development pre-release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next --prerelease dev --metadata $(shell git rev-parse --short HEAD))"
	git push --tags
