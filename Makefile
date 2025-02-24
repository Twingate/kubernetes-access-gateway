GOLANG_VERSION 		?= $(shell cat .tool-versions | grep golang | cut -d' ' -f2)
VERSION 	 		?= latest
REGISTRY 			?= twingate
IMAGE				:= kubernetes-gateway
IMAGE_NAME			:= $(REGISTRY)/$(IMAGE)
PLATFORMS 			?= linux/amd64,linux/arm/v7,linux/arm64
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
    print "  ${YELLOW}PLATFORMS${RESET}      = ${GREEN}$(PLATFORMS)${RESET}\n\n"; \
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

.PHONY: build-local
build-local: ##@build Build the container image locally
	@echo Building $(IMAGE_NAME)
	docker build --pull --target prod -t $(IMAGE_NAME):$(VERSION)-local . -f Dockerfile --build-arg GOLANG_VERSION=$(GOLANG_VERSION)
	docker build --pull --target debug -t $(IMAGE_NAME):$(VERSION)-local-debug . -f Dockerfile --build-arg GOLANG_VERSION=$(GOLANG_VERSION)

.PHONY: build
build: ##@build Build the container image
	@docker buildx create --use --name=${IMAGE} --node=${IMAGE} && \
	docker buildx build -o "type=image,push=false" --platform=$(PLATFORMS) --pull $(PROD_TAGS) -t $(IMAGE_NAME):latest . -f Dockerfile  --target prod --build-arg GOLANG_VERSION=$(GOLANG_VERSION) $(DOCKER_BUILDX_CACHE)

.PHONY: publish
publish: ##@build Push the image to the remote registry
	@docker buildx create --use --name=${IMAGE} --node=${IMAGE} && \
	docker buildx build -o "type=image,push=true" --platform=$(PLATFORMS) --pull $(PROD_TAGS) -t $(IMAGE_NAME):latest . -f Dockerfile  --target prod --build-arg GOLANG_VERSION=$(GOLANG_VERSION) $(DOCKER_BUILDX_CACHE)
