# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

K8sGPT is a Kubernetes debugging tool that scans clusters for issues and uses AI backends to explain problems in plain English. It features pluggable analyzers, AI backends, integrations, and caching.

## Common Commands

```bash
make build              # Build binary to ./bin/k8sgpt
make test               # Run all unit tests (go test ./...)
make lint               # Run golangci-lint (requires golangci-lint installed)
make fmt                # Format code
make vet                # Run go vet
make style              # Run fmt + vet + lint
make tidy               # go mod tidy
make cover              # Run tests with coverage

# Run a single test
go test -v -run TestPodAnalyzer ./pkg/analyzer

# Run tests for a specific package
go test -v ./pkg/analyzer
```

## Architecture

### Plugin System (Four Extension Points)

All four extension points use interface-based plugin patterns with central registries:

1. **Analyzers** (`pkg/common/types.go:IAnalyzer`) - Scan K8s resources for issues. Each returns `[]Result` with failures found.
   - Core analyzers (always active): `pkg/analyzer/analyzer.go:coreAnalyzerMap` - Pod, Deployment, Service, Node, etc.
   - Additional analyzers (opt-in): `pkg/analyzer/analyzer.go:additionalAnalyzerMap` - HPA, NetworkPolicy, Gateway API, OLM, etc.
   - Integration-injected analyzers: added dynamically via `IIntegration.AddAnalyzer()`

2. **AI Backends** (`pkg/ai/iai.go:IAI`) - Generate explanations via `GetCompletion()`. 15 backends registered in `pkg/ai/iai.go:clients` slice. Factory: `ai.NewClient(providerName)`.

3. **Integrations** (`pkg/integration/integration.go:IIntegration`) - Third-party tool support (Prometheus, KEDA, Kyverno, AWS). Registered in `pkg/integration/integration.go:integrations` map. Activated via CLI, which calls `Deploy()` and injects analyzers.

4. **Cache** (`pkg/cache/cache.go:ICache`) - Result caching with multiple backends (file, S3, Azure Blob, GCS).

### Data Flow

CLI command (`cmd/analyze/`) -> `pkg/analysis/analysis.go` (orchestration) -> runs analyzers concurrently -> each analyzer queries K8s via `common.Analyzer.Client` -> failures sent to AI backend for explanation -> results cached and displayed.

### Server Mode

`pkg/server/` provides gRPC + HTTP (h2c multiplexed) on port 8080, with Prometheus metrics on 8081. MCP server support (`pkg/server/mcp.go`) enables Claude Desktop integration via stdio or HTTP mode.

### Configuration

Viper-based YAML config at `$XDG_CONFIG_HOME/k8sgpt/k8sgpt.yaml`. Environment variable prefix: `K8SGPT_`. Config initialized in `cmd/root.go:initConfig()`.

## Testing Patterns

Tests use `k8s.io/client-go/kubernetes/fake` for mock K8s clients and `testify/assert` for assertions. Pattern:

```go
clientset := fake.NewSimpleClientset(&v1.Pod{...})
config := common.Analyzer{
    Client:  &kubernetes.Client{Client: clientset},
    Context: context.Background(),
}
results, err := analyzer.Analyze(config)
```

Helper functions in `pkg/analyzer/test_utils.go` (e.g., `boolPtr`, `int64Ptr`). The `NoOpAIClient` in `pkg/ai/` is used for tests that don't need real AI responses.

## Adding New Components

**New Analyzer**: Create `pkg/analyzer/<resource>.go` implementing `IAnalyzer`, register in `coreAnalyzerMap` or `additionalAnalyzerMap` in `pkg/analyzer/analyzer.go`, add tests with fake clientsets.

**New AI Backend**: Create `pkg/ai/<backend>.go` implementing `IAI`, add to `clients` slice and `Backends` list in `pkg/ai/iai.go`.

**New Integration**: Create `pkg/integration/<name>/<name>.go` implementing `IIntegration`, register in `pkg/integration/integration.go:integrations` map.

## Conventions

- Uses conventional commits (`feat:`, `fix:`, `chore:`) for Release Please auto-versioning
- PR titles must be semantic and start lowercase — CI enforces allowed types: `feat`, `fix`, `build`, `chore`, `ci`, `docs`, `perf`, `refactor`, `revert`, `style`, `test`, `deps`
- Fork workflow: branches on origin (personal fork), PRs against upstream/main
- Run `make style` (fmt + vet + lint) before submitting — this is the pre-PR quality gate
- Linting uses golangci-lint v2.1.0 with default config (no `.golangci.yml` in repo)
- Apache 2.0 license headers on all source files
- `pkg/util/util.go` contains anonymization logic for masking K8s object names before sending to AI backends
- Build uses `CGO_ENABLED=0` for static binaries with ldflags version injection
