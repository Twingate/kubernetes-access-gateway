ARG GOLANG_VERSION
ARG TARGETOS
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM  golang:${GOLANG_VERSION} AS builder
WORKDIR /twingate
COPY . .
RUN go mod download && go mod verify
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/go-delve/delve/cmd/dlv@latest && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build main.go

FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian12:nonroot AS prod
LABEL org.opencontainers.image.source=https://github.com/Twingate/kubernetes-access-gateway
WORKDIR /app
COPY --from=builder /twingate/main .
ENTRYPOINT ["./main", "start"]

FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian12:debug AS debug
LABEL org.opencontainers.image.source=https://github.com/Twingate/kubernetes-access-gateway
WORKDIR /app
COPY --from=builder /twingate/main .
COPY --from=builder /go/bin/dlv .
ENTRYPOINT ["./dlv", "exec", "./main", "--headless", "--listen=:2345", "--api-version=2", "--accept-multiclient", "--continue", "--", "start"]
