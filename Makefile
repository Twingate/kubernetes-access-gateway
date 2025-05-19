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
    for (sort keys %help) { \
    print "${WHITE}$$_:${RESET}\n"; \
    for (@{$$help{$$_}}) { \
    $$sep = " " x (32 - length $$_->[0]); \
    print "  ${YELLOW}$$_->[0]${RESET}$$sep${GREEN}$$_->[1]${RESET}\n"; \
    }; \
    print "\n"; }

.PHONY: help
help: ##@other Shows this help.
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

.PHONY: version
version: ##@other Show the version
	@echo $(VERSION)

.PHONY: lint
lint: ##@test Run Linter
	@echo "Running Linter..."
	golangci-lint run --fix ./...

.PHONY: lint-dockerfile
lint-dockerfile: ##@checks Lints Dockerfile
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser-debug

.PHONY: test-helm
test-helm: ##@test Run helm-unittest
	@echo "Running Helm unittest"
	helm unittest deploy/gateway

.PHONY: test-helm-and-update-snapshots
test-helm-and-update-snapshots: ##@test Run helm-unittest and also update the test snapshots
	@echo "Running Helm unittest and update test snapshots"
	helm unittest deploy/gateway -u

.PHONY: test
test: ##@test Run Tests
	@echo "Running Tests..."
	go test -race -v ./...

.PHONY: prepare-buildx
prepare-buildx: ##@build Prepare buildx
	@echo "Preparing buildx..."
	docker buildx create --use --name $(DOCKER_BUILDX_BUILDER) --node=$(DOCKER_BUILDX_BUILDER)

.PHONY: build
build: prepare-buildx ##@build Build the go binaries and container images
	DOCKER_BUILDX_BUILDER=$(DOCKER_BUILDX_BUILDER) GOLANG_VERSION=$(GOLANG_VERSION) IMAGE_REGISTRY=$(REGISTRY) goreleaser release --snapshot --clean

.PHONY: cut-release-prod
cut-release-prod: ##@release Cut a new release (create a version tagt and push it)
	echo "🚀 Cutting a new release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next)"
	git push --tags

.PHONY: cut-release-dev
cut-release: ##@release Cut a new release (create a version tagt and push it)
	echo "🚀 Cutting a new release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next --prerelease dev --metadata $(shell git rev-parse --short HEAD))"
	git push --tags

