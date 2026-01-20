# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

K8sGPT is a CLI tool that scans Kubernetes clusters, diagnoses issues, and triages problems using AI. It integrates with multiple AI backends (OpenAI, Azure, Cohere, Amazon Bedrock, Google Gemini, Ollama, and others) to provide explanations for detected issues.

## Build Commands

```bash
# Build binary
make build              # Outputs to bin/k8sgpt

# Run tests
make test               # Run all unit tests
go test ./...           # Alternative: run tests directly
go test ./pkg/analyzer  # Run tests for a specific package

# Linting and formatting
make lint               # Requires golangci-lint
make fmt                # Format code
make vet                # Run go vet

# Docker
make docker-build-local # Build local docker image
```

## Architecture

### Entry Points
- `main.go` - Entry point, calls `cmd.Execute()`
- `cmd/root.go` - Cobra root command, initializes all subcommands

### Core Packages

**`pkg/analyzer/`** - Kubernetes resource analyzers
- Each analyzer implements `common.IAnalyzer` interface with `Analyze(common.Analyzer) ([]Result, error)`
- `coreAnalyzerMap` - Default analyzers (Pod, Deployment, Service, etc.)
- `additionalAnalyzerMap` - Optional analyzers (HPA, PDB, NetworkPolicy, GatewayAPI, etc.)

**`pkg/ai/`** - AI backend implementations
- `iai.go` - `IAI` interface that all backends implement: `Configure()`, `GetCompletion()`, `GetName()`, `Close()`
- Supported backends: OpenAI, Azure, LocalAI, Ollama, Cohere, Amazon Bedrock, Google Gemini, Huggingface, Groq, and more
- `prompts.go` - Prompt templates for AI explanations

**`pkg/analysis/`** - Analysis orchestration
- `analysis.go` - `Analysis` struct coordinates running analyzers, caching, and AI explanations
- `NewAnalysis()` - Factory function that sets up Kubernetes client, cache, and AI client
- `RunAnalysis()` - Executes analyzers concurrently based on filters

**`pkg/integration/`** - Third-party integrations
- Prometheus, AWS, KEDA, Kyverno
- Each implements `IIntegration` interface for deployment and custom analyzers

**`pkg/server/`** - gRPC and MCP server implementations for `k8sgpt serve`

**`pkg/kubernetes/`** - Kubernetes client wrapper

**`pkg/cache/`** - Caching layer (file-based, S3, Azure Blob, GCS)

### Adding a New Analyzer

1. Create `pkg/analyzer/<resource>.go` implementing `common.IAnalyzer`
2. Add to `coreAnalyzerMap` or `additionalAnalyzerMap` in `pkg/analyzer/analyzer.go`
3. Create corresponding test file `pkg/analyzer/<resource>_test.go`

### Adding a New AI Backend

1. Create `pkg/ai/<backend>.go` implementing `IAI` interface
2. Add client to `clients` slice in `pkg/ai/iai.go`
3. Add backend name to `Backends` slice in `pkg/ai/iai.go`

## Configuration

Config file location: `$XDG_CONFIG_HOME/k8sgpt/k8sgpt.yaml` (typically `~/.config/k8sgpt/k8sgpt.yaml`)

Environment variables are prefixed with `K8SGPT_` (e.g., `K8SGPT_BACKEND`, `K8SGPT_PASSWORD`).

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `chore:` - Build/tooling changes
- `refactor:` - Code refactoring
- `test:` - Tests

Commits must be signed off (DCO): `git commit --signoff`
