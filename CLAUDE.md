# Twingate Kubernetes Access Gateway - AI Development Guide

## 1. Project Overview

**Project Name**: Twingate Kubernetes Access Gateway
**License**: MPL-2.0
**Repository**: https://github.com/Twingate/kubernetes-access-gateway

### Purpose
Zero-trust access gateway that bridges Twingate's secure access platform with Kubernetes clusters. Enables secure, authenticated access to Kubernetes API servers and SSH-enabled resources through Twingate's security policies without exposing cluster credentials.

### Key Capabilities
- **HTTP/Kubernetes API Proxy**: Secure tunnel to Kubernetes API servers with user impersonation
- **SSH Proxy**: Certificate-based SSH access to resources via gateway
- **JWT Authentication**: Twingate Access Token (GAT) with Proof-of-Possession validation
- **Zero-Trust Architecture**: TLS 1.3 mutual authentication, no credential exposure
- **Session Recording**: Audit logging for compliance and security monitoring
- **Metrics & Monitoring**: Prometheus metrics, Grafana dashboards

### Technology Stack
- **Language**: Go 1.26.0
- **Core Dependencies**:
  - `k8s.io/client-go` (v0.35.x) - Kubernetes client
  - `golang.org/x/crypto/ssh` - SSH protocol handling
  - `github.com/golang-jwt/jwt/v5` - JWT token parsing
  - `github.com/prometheus/client_golang` - Metrics
  - `github.com/spf13/cobra` - CLI framework
  - `go.uber.org/zap` - Structured logging
  - HashiCorp Vault SDK (optional CA management)
- **Build Tools**: goreleaser, Docker buildx, kind (local testing)
- **Linting**: golangci-lint v2.9 with revive rules
- **Testing**: testify, helm-unittest

## 2. Architecture Overview

### Startup Flow
```
main.go
  └─> cmd/root.go (Cobra CLI setup)
       └─> cmd/start.go (start command)
            └─> proxy.NewProxy() (internal/proxy/proxy.go)
                 ├─> token.NewParser() (JWT validation setup)
                 ├─> connect.NewCertReloader() (TLS cert hot-reload)
                 ├─> httphandler.NewConfig() (K8s proxy config)
                 └─> sshhandler.NewConfig() (SSH proxy config)
            └─> proxy.Start()
                 ├─> connect.NewListener() (TLS + protocol multiplexing)
                 ├─> sshhandler.NewProxy().Start() (SSH handler goroutine)
                 ├─> httphandler.NewProxy().Start() (HTTP handler goroutine)
                 └─> metrics.Start() (Prometheus endpoint)
```

### Core Components

#### Proxy Orchestrator (`internal/proxy/proxy.go`)
Central coordinator that:
- Initializes TLS configuration with cert auto-reloading
- Creates JWT token parser for Twingate network
- Launches protocol-specific handlers (HTTP/SSH) as goroutines
- Manages lifecycle using `errgroup` for coordinated shutdown
- Starts Prometheus metrics server on separate port

#### Connection Handler (`internal/connect/`)
- **`listener.go`**: Protocol multiplexer - accepts TLS connections and routes to HTTP or SSH based on initial handshake
- **`connect.go`**: Validates CONNECT requests with JWT + Proof-of-Possession (EKM signature)
- **`cert_reloader.go`**: Hot-reloads TLS certificates without restart
- **`conn.go`**: Wraps connections with metadata (user claims, connection ID)
- **`metrics.go`**: Tracks connection lifecycle metrics

#### HTTP Handler (`internal/httphandler/`)
- **`http_proxy.go`**: Reverse proxy to Kubernetes API servers
- **`config.go`**: Per-upstream K8s client configuration
- **`audit_middleware.go`**: HTTP request/response logging to session recorder
- **`wshijacker/`**: WebSocket upgrade handling for kubectl exec/logs

Supports multiple upstreams with:
- In-cluster mode (uses pod service account)
- External cluster mode (custom bearer token + CA)
- User impersonation (maps Twingate user to K8s identity)

#### SSH Handler (`internal/sshhandler/`)
- **`proxy.go`**: SSH server that accepts client connections
- **`ca.go`**: Certificate authority management (auto-generated, manual, or Vault)
- **`cert.go`**: SSH certificate generation (host + user certs)
- **`keys.go`**: SSH key pair generation (Ed25519/ECDSA/RSA)
- **`channel_pair.go`**: Bidirectional channel forwarding
- **`request_handler.go`**: SSH protocol request handling

Architecture:
1. Client connects to gateway SSH server
2. Gateway validates client certificate from CA
3. Gateway generates user certificate for upstream
4. Gateway connects to upstream SSH server
5. Channels are bidirectionally forwarded

#### Token Parser (`internal/token/`)
- **`parser.go`**: Fetches JWKS from Twingate and validates JWTs
- **`gat_claims.go`**: Twingate Access Token claims structure
- **`bearer_token_parser.go`**: Extracts bearer token from Proxy-Authorization header

Claims include:
- User identity (email, ID, name)
- Resource info (address, name, protocols)
- Client public key (for Proof-of-Possession)
- Twingate network metadata

#### Session Recorder (`internal/sessionrecorder/`)
Records audit logs with configurable flush intervals and size thresholds. Logs are structured (JSON) and include:
- User identity
- Timestamp
- Request/response details
- Connection metadata

#### Metrics (`internal/metrics/`)
- **`metrics.go`**: Prometheus HTTP server
- **`http_middleware.go`**: HTTP request metrics
- **`round_tripper.go`**: K8s client metrics
- Custom metrics for connections, requests, session recordings

### Security Model

#### Zero-Trust Architecture
- No long-lived credentials stored in gateway
- All access validated per-connection via Twingate tokens
- TLS 1.3 mutual authentication
- Certificate rotation without downtime

#### Token Validation Flow
1. Client sends CONNECT request with:
   - `Proxy-Authorization: Bearer <JWT>`
   - `X-Token-Signature: <base64(ECDSA_signature(TLS_EKM))>`
   - `X-Connection-Id: <UUID>`
2. Gateway validates JWT signature using JWKS from Twingate
3. Gateway extracts client public key from JWT claims
4. Gateway verifies signature over TLS Exported Key Material (Proof-of-Possession)
5. Gateway verifies requested address matches token resource
6. Connection is allowed and user identity is extracted

#### Kubernetes Security
- Gateway impersonates users via K8s impersonation headers
- No K8s service account tokens exposed to clients
- RBAC enforced at Kubernetes API server level
- Audit logs capture all API requests with user context

#### SSH Security
- Certificate-based authentication (no passwords)
- CA options: auto-generated, manual private key, or HashiCorp Vault
- Host certificates prove gateway identity to clients
- User certificates prove gateway identity to upstreams
- Optional separate CAs for different purposes (Vault advanced mode)

## 3. Directory Structure

```
/Users/ekampf/workspace/twingate/kubernetes-access-gateway/
├── cmd/                          # CLI commands (Cobra)
│   ├── root.go                   # Root command setup
│   ├── start.go                  # Main start command
│   └── *_test.go                 # Command tests
├── internal/                     # Internal packages (not importable)
│   ├── config/                   # Configuration loading and validation
│   │   └── config.go             # YAML config structs + validation
│   ├── connect/                  # Connection handling and TLS
│   │   ├── listener.go           # Protocol multiplexing listener
│   │   ├── connect.go            # CONNECT message validation
│   │   ├── cert_reloader.go      # TLS certificate hot-reload
│   │   ├── conn.go               # Connection wrapper
│   │   └── metrics.go            # Connection metrics
│   ├── httphandler/              # HTTP/Kubernetes proxy
│   │   ├── http_proxy.go         # Main reverse proxy logic
│   │   ├── config.go             # K8s client configuration
│   │   ├── audit_middleware.go   # Request logging
│   │   └── wshijacker/           # WebSocket upgrade handling
│   ├── sshhandler/               # SSH proxy
│   │   ├── proxy.go              # SSH server implementation
│   │   ├── ca.go                 # Certificate authority
│   │   ├── cert.go               # Certificate generation
│   │   ├── keys.go               # Key pair generation
│   │   ├── channel_pair.go       # Channel forwarding
│   │   └── request_handler.go    # SSH request handling
│   ├── token/                    # JWT token parsing
│   │   ├── parser.go             # JWKS fetching + validation
│   │   ├── gat_claims.go         # Token claims structure
│   │   └── bearer_token_parser.go
│   ├── sessionrecorder/          # Audit logging
│   │   └── recorder.go
│   ├── metrics/                  # Prometheus metrics
│   │   ├── metrics.go            # Metrics server
│   │   ├── http_middleware.go
│   │   └── round_tripper.go
│   ├── log/                      # Logging utilities
│   │   └── logger.go
│   └── version/                  # Version information
│       └── version.go
├── deploy/gateway/               # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── templates/                # K8s manifests
│   └── tests/                    # Helm unit tests
├── test/                         # Test suites
│   ├── integration/              # Integration tests (kind cluster)
│   │   ├── kubernetes_test.go
│   │   ├── ssh_test.go
│   │   ├── concurrent_users_test.go
│   │   └── testutil/             # Test helpers
│   ├── e2e/                      # End-to-end tests
│   │   └── e2e_test.go
│   ├── data/                     # Test data (certs, keys)
│   └── fake/                     # Mock implementations
├── tools/local/                  # Local development tools
│   ├── main.go                   # Local dev server
│   ├── kind.go                   # Kind cluster setup
│   └── ssh.go                    # SSH server setup
├── .github/workflows/            # GitHub Actions CI/CD
│   ├── ci.yaml                   # Main CI pipeline
│   └── release.yaml              # Release automation
├── main.go                       # Application entry point
├── Makefile                      # Build automation
├── .goreleaser.yaml              # Release configuration
├── .golangci.yml                 # Linter configuration
├── .tool-versions                # asdf tool versions
├── go.mod                        # Go module dependencies
├── go.sum                        # Dependency checksums
├── Dockerfile.goreleaser         # Production image
├── Dockerfile.goreleaser-debug   # Debug image
└── README.md                     # User documentation
```

## 4. Critical Files Reference

All paths are absolute for precision.

### Core Flow
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/main.go`**
  Entry point, invokes Cobra CLI

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/cmd/start.go`**
  Start command implementation, config loading, proxy initialization

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/proxy/proxy.go`**
  Central orchestrator, lifecycle management, goroutine coordination

### Configuration
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config.go`**
  Configuration structs, validation logic, defaults, YAML parsing
  Key concepts: TwingateConfig, KubernetesUpstream, SSHConfig, SSHCAConfig

### Security & Authentication
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/connect.go`**
  CONNECT message validation, JWT parsing, Proof-of-Possession verification
  Validates: HTTP method, bearer token, signature, destination address

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/token/parser.go`**
  JWKS fetching from Twingate, JWT signature validation

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/token/gat_claims.go`**
  Twingate Access Token claims structure (user, resource, client key)

### Protocol Handlers
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/http_proxy.go`**
  Kubernetes API reverse proxy, impersonation headers, upstream selection
  Key function: `Start()`, `ServeHTTP()`, impersonation header injection

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sshhandler/proxy.go`**
  SSH server implementation, client authentication, upstream connection
  Key function: `Start()`, `handleConnection()`, certificate validation

### Connection Handling
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/listener.go`**
  Protocol multiplexing, routes connections to HTTP or SSH handlers
  Uses initial byte peek to differentiate protocols

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/cert_reloader.go`**
  Hot-reloads TLS certificates via file watcher

### Deployment
- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/values.yaml`**
  Helm chart default values, configuration options

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/templates/deployment.yaml`**
  Kubernetes Deployment manifest

- **`/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.goreleaser.yaml`**
  Multi-arch Docker builds, release automation

## 5. Development Workflows

### Environment Setup
```bash
# Install Go 1.26.0 (via asdf)
asdf install golang 1.26.0

# Install golangci-lint v2.9
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.9.0

# Install development tools
go install github.com/caarlos0/svu@latest      # Semantic versioning
go install github.com/vektra/mockery/v2@latest # Mock generation

# Install kind for local testing
go install sigs.k8s.io/kind@latest
```

All versions are tracked in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.tool-versions`.

### Build Commands
```bash
# Build locally (all platforms via goreleaser)
make build

# Get current version
make version

# Quick compile (single platform)
go build -o dist/gateway .
```

### Testing Strategy

**Unit Tests** (`./cmd/...`, `./internal/...`)
```bash
make test                    # Run all unit tests
make test-with-coverage      # With coverage report
go test -v ./internal/proxy  # Single package
```

**Integration Tests** (`./test/integration/...`)
- Requires kind cluster
- Tests full protocol flows (K8s API, SSH)
- Validates authentication, impersonation, session recording
```bash
make test-integration
make test-integration-with-coverage
```

**E2E Tests** (`./test/e2e/...`)
- Full deployment scenario
```bash
make test-e2e
```

**Helm Tests** (`deploy/gateway/tests/...`)
```bash
make test-helm                          # Run snapshot tests
make test-helm-and-update-snapshots     # Update test snapshots
```

**Coverage Reporting**
```bash
make test-with-coverage test-integration-with-coverage coverall
```

### Linting
Configuration: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.golangci.yml`

```bash
make lint               # Auto-fix issues
golangci-lint run       # Check only
```

Key rules:
- All linters enabled by default
- Revive with all rules (some disabled: cognitive-complexity, function-length)
- Copyright header enforcement (MPL-2.0)
- Import ordering via gci formatter

### Release Process

**Development Pre-Release** (from `master` branch)
```bash
make cut-release-dev
# Creates tag: v1.2.3-dev-abc1234
# Triggers CI to build and push Docker images with dev tag
```

**Production Release** (from `master` branch)
```bash
make cut-release-prod
# Creates tag: v1.2.4
# Triggers CI to build and push Docker images with version tag
```

Version calculation uses `svu` (semantic version util) based on conventional commits.

### CI/CD Pipeline
Workflow: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.github/workflows/ci.yaml`

On every push:
1. Go linting (golangci-lint)
2. Unit tests with coverage
3. Integration tests with kind cluster
4. Helm chart linting and unit tests
5. Coverage upload to Coveralls

On tag push:
1. All CI steps
2. goreleaser multi-arch Docker build (linux/amd64, linux/arm64)
3. Push to Docker Hub (twingate/kubernetes-gateway)
4. GitHub release creation

## 6. Code Patterns & Conventions

### Code Organization
- **Internal packages**: All application code in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/` (not importable externally)
- **Package naming**: Lowercase, singular nouns (e.g., `proxy`, `config`, not `proxies`, `configs`)
- **Interfaces**: Defined in consumer packages, not provider packages
- **Dependency injection**: Pass dependencies via constructors (`NewXxx()` functions)

### Error Handling
- **Sentinel errors**: Use package-level variables for expected errors
  ```go
  var ErrRequired = errors.New("required field is missing")
  ```
- **Error wrapping**: Use `fmt.Errorf("context: %w", err)` for stack context
- **Error types**: Custom types (e.g., `HTTPError`) for protocol-specific errors
- **No panic**: Avoid panic in production code; return errors

### Configuration
- **YAML config**: Load via `config.Load(path)` in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config.go`
- **Validation**: `Validate()` methods on all config structs
- **Defaults**: Set in `newDefaultConfig()`, not in struct tags
- **Sentinel values**: Use pointers for optional fields (e.g., `*KubernetesConfig`)

### Testing
- **Table-driven tests**: Use slice of test cases
  ```go
  tests := []struct {
      name    string
      input   string
      want    string
      wantErr error
  }{ /* cases */ }
  ```
- **Testify**: Use `require` for assertions (fails fast)
- **Mocks**: Generate via mockery, store in same package as interface
- **Test helpers**: In `test/integration/testutil/` for integration tests

### Linting Configuration
File: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.golangci.yml`

Custom settings:
- Timeout: 2 minutes
- Disabled linters: cyclop, dupl, exhaustruct, funlen, varnamelen, wrapcheck
- Revive: All rules enabled except cognitive-complexity, function-length, flag-parameter
- Copyright header required (MPL-2.0)
- YAML tags: goCamel case

### Commit Messages
Follow conventional commits:
```
feat: add SSH certificate rotation
fix: resolve token validation race condition
chore: upgrade golangci-lint to v2.9
docs: update installation guide
test: add integration test for concurrent users
```

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `ci`

## 7. Security Model Deep Dive

### Zero-Trust Principles
1. **No Trust in Network Location**: Even within K8s cluster, all connections authenticated
2. **Verify Explicitly**: Every connection requires valid JWT + signature
3. **Least Privilege**: Users get K8s permissions via RBAC, not gateway permissions
4. **Assume Breach**: Session recording enables post-incident analysis

### Token Validation Flow (Detailed)
Located in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/connect.go`

```
Client                          Gateway                         Twingate API
  |                                |                                    |
  |-- TLS Handshake ------------->|                                    |
  |                                |-- Fetch JWKS ------------------>  |
  |                                |<-- Return Public Keys ----------  |
  |                                |                                    |
  |-- CONNECT resource:443 ------>|                                    |
  |   Proxy-Authorization: Bearer JWT                                  |
  |   X-Token-Signature: <sig>                                         |
  |                                |                                    |
  |                                |-- Verify JWT signature            |
  |                                |-- Extract TLS EKM (export key)    |
  |                                |-- Verify sig = ECDSA(EKM, client_pubkey) |
  |                                |-- Verify resource address matches |
  |                                |                                    |
  |<-- HTTP 200 Connection Est. --|                                    |
```

**Proof-of-Possession (PoP)**:
- TLS Exported Key Material (EKM) is unique per TLS session
- Client signs EKM with private key corresponding to public key in JWT
- Prevents token theft: stolen JWT is useless without private key

### Kubernetes Security (Detailed)
Located in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/http_proxy.go`

**Impersonation Headers**:
```go
// Gateway adds these headers before forwarding to K8s API
req.Header.Set("Impersonate-User", claims.User.Email)
req.Header.Set("Impersonate-Group", "twingate:authenticated")
// Optional: Impersonate-Extra-* headers for custom attributes
```

**Benefits**:
- K8s RBAC sees actual user identity, not gateway service account
- Audit logs show real user, not "system:serviceaccount:gateway"
- No need to distribute kubeconfig files to users
- Gateway service account only needs impersonation permission

**Configuration Example**:
```yaml
# /Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/values.yaml
kubernetes:
  upstreams:
    - name: production
      inCluster: true          # Use pod service account
    - name: staging
      inCluster: false
      address: https://staging-k8s.example.com:6443
      bearerTokenFile: /var/run/secrets/staging-token
      caFile: /var/run/secrets/staging-ca.crt
```

### SSH Security (Detailed)
Located in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sshhandler/`

**Certificate Architecture**:
1. **Gateway Host Certificate** (`ca.go:L100-L150`)
   - Signed by CA, presented to SSH clients
   - Proves gateway identity
   - TTL configurable (default: 24h)

2. **Gateway User Certificate** (`cert.go:L50-L100`)
   - Signed by CA, presented to upstream SSH servers
   - Includes Twingate user identity as principals
   - TTL configurable (default: 1h)

3. **Upstream Host Verification** (`ca.go:L200-L250`)
   - Gateway verifies upstream server certificates against CA

**CA Options**:
- **Auto-generated**: Ephemeral CA created on startup (for testing)
- **Manual**: Load private key from file (for persistent CA)
- **Vault**: Integrate with HashiCorp Vault SSH secret engine
  - Supports separate CAs for host/user/upstream
  - Automatic certificate rotation
  - Centralized CA management

**Vault Advanced Configuration**:
```yaml
# /Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config.go
ssh:
  ca:
    vault:
      address: https://vault.example.com
      auth:
        token: <token>
      mount: ssh              # Default mount for all CAs
      role: gateway           # Default role for all CAs
      gatewayHostCA:          # Override for host certs
        mount: ssh-host
        role: gateway-host
      gatewayUserCA:          # Override for user certs
        mount: ssh-user
        role: gateway-user
      upstreamHostCA:         # Override for upstream verification
        mount: ssh-upstream   # (no role needed, just public key)
```

## 8. Common Tasks

### Adding New Configuration Options

**Step 1**: Define config struct in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config.go`
```go
type MyFeatureConfig struct {
    Enabled bool   `yaml:"enabled"`
    Timeout int    `yaml:"timeout"`
}
```

**Step 2**: Add field to parent config
```go
type Config struct {
    // ... existing fields
    MyFeature *MyFeatureConfig `yaml:"myFeature,omitempty"`
}
```

**Step 3**: Add validation
```go
func (c *Config) Validate() error {
    // ... existing validation
    if c.MyFeature != nil {
        if err := c.MyFeature.Validate(); err != nil {
            return fmt.Errorf("myFeature: %w", err)
        }
    }
    return nil
}

func (m *MyFeatureConfig) Validate() error {
    if m.Timeout < 0 {
        return fmt.Errorf("timeout must be non-negative")
    }
    return nil
}
```

**Step 4**: Add tests in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config_test.go`

**Step 5**: Update Helm chart values in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/values.yaml`

### Adding New Metrics

**Step 1**: Define metric in package that uses it (e.g., `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/mypackage/metrics.go`)
```go
var (
    myCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "gateway",
            Subsystem: "myfeature",
            Name:      "requests_total",
            Help:      "Total number of requests processed",
        },
        []string{"status"},
    )
)

func RegisterMetrics(registry *prometheus.Registry) {
    registry.MustRegister(myCounter)
}
```

**Step 2**: Call `RegisterMetrics()` from `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/proxy/proxy.go`

**Step 3**: Instrument code
```go
myCounter.WithLabelValues("success").Inc()
```

**Step 4**: Add tests in `metrics_test.go`

**Step 5**: Document in Grafana dashboard (if relevant)

### Adding New HTTP Handlers

**Step 1**: Create handler in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/`
```go
func MyHandler(upstream *kubernetes.Clientset) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Implementation
    }
}
```

**Step 2**: Register in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/http_proxy.go`
```go
mux.HandleFunc("/my/path", MyHandler(upstream))
```

**Step 3**: Add middleware if needed (audit, metrics)
```go
handler = auditMiddleware(handler)
handler = metricsMiddleware(handler)
```

**Step 4**: Add integration test in `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/test/integration/kubernetes_test.go`

### Debugging Connection Issues

**Enable Debug Logging**:
```bash
# Set log level to debug
export LOG_LEVEL=debug
./dist/gateway start --config config.yaml
```

**Check TLS Handshake**:
```bash
# Test TLS connection
openssl s_client -connect localhost:8443 -showcerts
```

**Validate JWT Token**:
```bash
# Decode JWT (without verification)
echo "<token>" | cut -d. -f2 | base64 -d | jq .
```

**Check Metrics**:
```bash
# Query Prometheus endpoint
curl http://localhost:9090/metrics | grep gateway_
```

**Common Issues**:
1. **401 Unauthorized**: JWT signature validation failed
   - Check token expiration
   - Verify JWKS endpoint is reachable
   - Validate token issuer matches Twingate network

2. **Connection Refused**: Upstream unreachable
   - Check upstream address in config
   - Verify network connectivity
   - Review firewall rules

3. **Impersonation Denied**: K8s RBAC issue
   - Gateway service account needs `impersonate` permission
   - User being impersonated must have RBAC bindings

### Working with Tests

**Run Specific Test**:
```bash
go test -v ./internal/proxy -run TestProxyStart
```

**Run with Race Detector**:
```bash
go test -race ./...
```

**Update Integration Test Expectations**:
```bash
# Integration tests use golden files in test/integration/testdata/
# Update after intentional changes:
go test ./test/integration -update
```

**Debug Test with Delve**:
```bash
dlv test ./internal/proxy -- -test.run TestProxyStart
```

## 9. Key Dependencies

### Core Dependencies
- **`k8s.io/client-go@v0.35.1`**: Kubernetes API client
  - Used in: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/config.go`
  - Purpose: Create K8s clientsets, REST configs, impersonation

- **`golang.org/x/crypto/ssh`**: SSH protocol implementation
  - Used in: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sshhandler/`
  - Purpose: SSH server, client, certificate handling

- **`github.com/golang-jwt/jwt/v5`**: JWT parsing and validation
  - Used in: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/token/parser.go`
  - Purpose: Validate Twingate Access Tokens

- **`github.com/MicahParks/keyfunc/v3`**: JWKS fetching and caching
  - Used in: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/token/parser.go`
  - Purpose: Fetch public keys from Twingate JWKS endpoint

- **`github.com/prometheus/client_golang`**: Prometheus metrics
  - Used throughout for instrumentation

- **`go.uber.org/zap`**: Structured logging
  - Used throughout for logging

### HashiCorp Vault Integration (Optional)
- **`github.com/hashicorp/vault/api`**: Vault client
  - Used in: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sshhandler/ca.go`
  - Purpose: Sign SSH certificates via Vault SSH secret engine

### Development Tools
- **`github.com/stretchr/testify`**: Testing assertions and mocks
- **`sigs.k8s.io/kind`**: Local Kubernetes clusters for testing
- **`github.com/caarlos0/svu`**: Semantic version calculation

## 10. Deployment

### Helm Chart Overview
Location: `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/`

**Key Resources**:
- Deployment: Gateway pods with configurable replicas
- Service: ClusterIP/LoadBalancer for client connections
- ServiceAccount: For K8s API access
- ClusterRole/Binding: Impersonation permissions
- Secret: TLS certificates, SSH keys
- ConfigMap: Gateway configuration YAML

**High Availability**:
```yaml
# /Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/values.yaml
replicaCount: 3

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app
              operator: In
              values:
                - gateway
        topologyKey: kubernetes.io/hostname
```

**Resource Requests/Limits**:
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

### Configuration Management

**Secrets**:
- TLS certificate and private key (auto-generated or provided)
- SSH CA private key (if manual mode)
- Vault token (if Vault CA mode)
- Upstream K8s bearer tokens (if external clusters)

**ConfigMaps**:
- Gateway configuration YAML
- Upstream CA certificates

**Example ConfigMap**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-config
data:
  config.yaml: |
    twingate:
      network: example
    port: 8443
    metricsPort: 9090
    kubernetes:
      upstreams:
        - name: production
          inCluster: true
    ssh:
      gateway:
        username: gateway
        key:
          type: ed25519
        hostCertificate:
          ttl: 24h
        userCertificate:
          ttl: 1h
      ca:
        manual:
          privateKeyFile: /etc/gateway/ssh-ca-key
      upstreams:
        - name: bastion
          address: bastion.example.com:22
```

### Monitoring

**Prometheus Metrics**:
- Endpoint: `:9090/metrics`
- Namespace: `gateway_`
- Key metrics:
  - `gateway_connections_total`: Connection counts by protocol, status
  - `gateway_http_requests_total`: HTTP request counts by upstream, method, status
  - `gateway_http_request_duration_seconds`: Request latency histogram
  - `gateway_session_recordings_total`: Session recording counts by status

**Grafana Dashboard**:
- Available in GitHub wiki or `docs/` directory
- Panels: connection rate, request latency, error rate, active connections

**Alerts** (Example Prometheus rules):
```yaml
groups:
  - name: gateway
    rules:
      - alert: HighErrorRate
        expr: |
          rate(gateway_http_requests_total{status=~"5.."}[5m])
          / rate(gateway_http_requests_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: "Gateway error rate > 5%"
```

## 11. Troubleshooting

### Connection Refused

**Symptoms**: Client cannot connect to gateway

**Diagnosis**:
```bash
# Check if gateway is listening
netstat -tlnp | grep 8443

# Check gateway logs
kubectl logs -f deployment/gateway

# Check service endpoints
kubectl get endpoints gateway
```

**Solutions**:
- Verify gateway pod is running and ready
- Check service configuration (port, selector)
- Verify network policies allow ingress
- Check LoadBalancer provisioning (if type: LoadBalancer)

### Authentication Failures

**Symptoms**: 401 Unauthorized or 407 Proxy Authentication Required

**Diagnosis**:
```bash
# Check gateway logs for token validation errors
kubectl logs deployment/gateway | grep "failed to parse token"

# Verify JWKS endpoint is reachable from gateway pod
kubectl exec -it deployment/gateway -- curl https://<network>.twingate.com/.well-known/jwks.json

# Check token claims
echo "<token>" | cut -d. -f2 | base64 -d | jq .
```

**Common Causes**:
- Token expired (check `exp` claim)
- Wrong Twingate network in config
- JWKS endpoint unreachable (network policy, firewall)
- Invalid Proof-of-Possession signature (TLS version mismatch)

**Solutions**:
- Request new token from Twingate client
- Verify `twingate.network` in config matches token issuer
- Allow egress to `*.twingate.com` on port 443
- Ensure client and gateway both use TLS 1.3

### Kubernetes API Errors

**Symptoms**: 403 Forbidden when accessing K8s resources

**Diagnosis**:
```bash
# Check gateway service account permissions
kubectl auth can-i impersonate user/<email> --as=system:serviceaccount:<namespace>:gateway

# Check user RBAC
kubectl auth can-i get pods --as=<email>

# Review gateway logs
kubectl logs deployment/gateway | grep impersonate
```

**Common Causes**:
- Gateway service account lacks impersonation permission
- User has no RBAC bindings in K8s cluster
- Incorrect impersonation group/extra headers

**Solutions**:
- Grant impersonation permission:
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: gateway-impersonator
  rules:
    - apiGroups: [""]
      resources: ["users", "groups"]
      verbs: ["impersonate"]
  ```
- Create RBAC bindings for Twingate users:
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: developers
  subjects:
    - kind: User
      name: alice@example.com  # Matches Twingate user email
  roleRef:
    kind: Role
    name: developer
  ```

### SSH Connection Issues

**Symptoms**: SSH connection fails or hangs

**Diagnosis**:
```bash
# Enable verbose SSH client output
ssh -vvv -o ProxyCommand='...' user@upstream

# Check gateway logs
kubectl logs deployment/gateway | grep ssh

# Test upstream connectivity from gateway pod
kubectl exec -it deployment/gateway -- nc -zv upstream.example.com 22
```

**Common Causes**:
- Certificate validation failure (client or upstream)
- Upstream unreachable from gateway pod
- SSH CA configuration mismatch
- Certificate expired (TTL too short)

**Solutions**:
- Verify CA configuration matches client and upstream expectations
- Check network connectivity to upstream
- Increase certificate TTL if rotation is too frequent
- For Vault CA: verify mount paths and roles are correct

### Performance Issues

**Symptoms**: Slow response times, high latency

**Diagnosis**:
```bash
# Check resource usage
kubectl top pod -l app=gateway

# Check connection counts
curl http://localhost:9090/metrics | grep gateway_connections_active

# Review request latency
curl http://localhost:9090/metrics | grep gateway_http_request_duration_seconds
```

**Common Causes**:
- Insufficient CPU/memory resources
- Too few gateway replicas
- Slow upstream responses
- Session recording overhead

**Solutions**:
- Increase resource requests/limits
- Scale gateway replicas horizontally
- Optimize upstream cluster (if K8s API is slow)
- Adjust session recording flush interval to reduce write frequency

## 12. Quick Reference

### Critical Files (Absolute Paths)

| Purpose | File Path |
|---------|-----------|
| **Entry Point** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/main.go` |
| **Start Command** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/cmd/start.go` |
| **Proxy Orchestrator** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/proxy/proxy.go` |
| **Configuration** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/config/config.go` |
| **CONNECT Validation** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/connect.go` |
| **JWT Parser** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/token/parser.go` |
| **HTTP Proxy** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/httphandler/http_proxy.go` |
| **SSH Proxy** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sshhandler/proxy.go` |
| **Protocol Listener** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/connect/listener.go` |
| **Metrics** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/metrics/metrics.go` |
| **Session Recorder** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/internal/sessionrecorder/recorder.go` |
| **Build Config** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/Makefile` |
| **Lint Config** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.golangci.yml` |
| **Release Config** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/.goreleaser.yaml` |
| **Helm Chart** | `/Users/ekampf/workspace/twingate/kubernetes-access-gateway/deploy/gateway/` |

### Common Commands

| Task | Command |
|------|---------|
| **Build** | `make build` |
| **Test (Unit)** | `make test` |
| **Test (Integration)** | `make test-integration` |
| **Test (E2E)** | `make test-e2e` |
| **Test (Helm)** | `make test-helm` |
| **Coverage** | `make test-with-coverage` |
| **Lint** | `make lint` |
| **Version** | `make version` |
| **Cut Dev Release** | `make cut-release-dev` |
| **Cut Prod Release** | `make cut-release-prod` |

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `GOLANG_VERSION` | Go version for builds | `1.26.0` |
| `LOG_LEVEL` | Logging verbosity | `debug`, `info`, `warn`, `error` |
| `CONFIG_FILE` | Config file path | `/etc/gateway/config.yaml` |

---

## Notes for AI Assistants

1. **Always use absolute paths** when referencing files in this project
2. **Security is paramount**: Never bypass authentication, token validation, or certificate verification
3. **Follow existing patterns**: Use table-driven tests, sentinel errors, struct validation
4. **Lint before committing**: Run `make lint` to catch issues early
5. **Update tests**: Add/update tests for any code changes
6. **Document config changes**: Update Helm values and this guide for new config options
7. **Check backwards compatibility**: Avoid breaking changes to config schema or public APIs
8. **Use conventional commits**: Follow commit message format for automated versioning
9. **Consider multi-protocol**: Changes may affect both HTTP and SSH handlers
10. **Consult security model**: Authentication and authorization changes require careful review
