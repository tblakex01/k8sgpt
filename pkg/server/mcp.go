/*
Copyright 2024 The K8sGPT Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	schemav1 "buf.build/gen/go/k8sgpt-ai/k8sgpt/protocolbuffers/go/schema/v1"
	"github.com/k8sgpt-ai/k8sgpt/pkg/ai"
	"github.com/k8sgpt-ai/k8sgpt/pkg/analysis"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/policy"
	"github.com/k8sgpt-ai/k8sgpt/pkg/server/config"
	"github.com/k8sgpt-ai/k8sgpt/pkg/store"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// K8sGptMCPServer represents an MCP server for k8sgpt
type K8sGptMCPServer struct {
	server      *server.MCPServer
	port        string
	aiProvider  *ai.AIProvider
	useHTTP     bool
	logger      *zap.Logger
	httpServer  *server.StreamableHTTPServer
	stdioServer *server.StdioServer
}

func NewMCPServer(port string, aiProvider *ai.AIProvider, useHTTP bool, logger *zap.Logger) (*K8sGptMCPServer, error) {
	opts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
		server.WithPromptCapabilities(false),
	}

	// Create the MCP server
	mcpServer := server.NewMCPServer("k8sgpt", "1.0.0", opts...)
	var k8sGptMCPServer = &K8sGptMCPServer{
		server:     mcpServer,
		port:       port,
		aiProvider: aiProvider,
		useHTTP:    useHTTP,
		logger:     logger,
	}

	// Register tools and resources immediately
	if err := k8sGptMCPServer.registerToolsAndResources(); err != nil {
		return nil, fmt.Errorf("failed to register tools and resources: %v", err)
	}

	if useHTTP {
		// Create HTTP server with streamable transport
		httpOpts := []server.StreamableHTTPOption{
			server.WithLogger(&zapLoggerAdapter{logger: logger}),
			// Enable stateless mode for one-off tool invocations without session management
			server.WithStateLess(true),
		}

		httpServer := server.NewStreamableHTTPServer(mcpServer, httpOpts...)

		// Launch the HTTP server directly
		go func() {
			logger.Info("Starting MCP HTTP server", zap.String("port", port))
			if err := httpServer.Start(":" + port); err != nil {
				logger.Fatal("MCP HTTP server failed", zap.Error(err))
			}
		}()

		return &K8sGptMCPServer{
			server:     mcpServer,
			port:       port,
			aiProvider: aiProvider,
			useHTTP:    useHTTP,
			logger:     logger,
			httpServer: httpServer,
		}, nil
	} else {
		// Create stdio server
		stdioServer := server.NewStdioServer(mcpServer)

		return &K8sGptMCPServer{
			server:      mcpServer,
			port:        port,
			aiProvider:  aiProvider,
			useHTTP:     useHTTP,
			logger:      logger,
			stdioServer: stdioServer,
		}, nil
	}
}

// Start starts the MCP server
func (s *K8sGptMCPServer) Start() error {
	if s.server == nil {
		return fmt.Errorf("server not initialized")
	}
	// Register prompts
	if err := s.registerPrompts(); err != nil {
		return fmt.Errorf("failed to register prompts: %v", err)
	}
	// Register resources
	if err := s.registerResources(); err != nil {
		return fmt.Errorf("failed to register resources: %v", err)
	}

	// Start the server based on transport type
	if s.useHTTP {
		// HTTP server is already running in a goroutine
		return nil
	} else {
		// Start stdio server (this will block)
		return server.ServeStdio(s.server)
	}
}

func (s *K8sGptMCPServer) registerToolsAndResources() error {
	// Register analyze tool with proper JSON schema
	analyzeTool := mcp.NewTool("analyze",
		mcp.WithDescription("Analyze Kubernetes resources for issues and problems"),
		mcp.WithString("namespace",
			mcp.Description("Kubernetes namespace to analyze (empty for all namespaces)"),
		),
		mcp.WithString("backend",
			mcp.Description("AI backend to use for analysis (e.g., openai, azure, localai)"),
		),
		mcp.WithBoolean("explain",
			mcp.Description("Provide detailed explanations for issues"),
		),
		mcp.WithArray("filters",
			mcp.Description("Provide filters to narrow down the analysis (e.g. ['Pods', 'Deployments'])"),
			// without below line MCP server fails with Google Agent Development Kit (ADK), interestingly works fine with mcpinspector
			mcp.WithStringItems(),
		),
	)
	s.server.AddTool(analyzeTool, s.handleAnalyze)

	// Register cluster info tool (no parameters needed)
	clusterInfoTool := mcp.NewTool("cluster-info",
		mcp.WithDescription("Get Kubernetes cluster information and version"),
	)
	s.server.AddTool(clusterInfoTool, s.handleClusterInfo)

	// Register config tool with proper JSON schema
	configTool := mcp.NewTool("config",
		mcp.WithDescription("Configure K8sGPT settings including custom analyzers and cache"),
		mcp.WithObject("customAnalyzers",
			mcp.Description("Custom analyzer configurations"),
			mcp.Properties(map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name of the custom analyzer",
				},
				"connection": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"url": map[string]any{
							"type":        "string",
							"description": "URL of the custom analyzer service",
						},
						"port": map[string]any{
							"type":        "integer",
							"description": "Port of the custom analyzer service",
						},
					},
				},
			}),
		),
		mcp.WithObject("cache",
			mcp.Description("Cache configuration"),
			mcp.Properties(map[string]any{
				"type": map[string]any{
					"type":        "string",
					"description": "Cache type (s3, azure, gcs)",
					"enum":        []string{"s3", "azure", "gcs"},
				},
				"bucketName": map[string]any{
					"type":        "string",
					"description": "Bucket name for S3/GCS cache",
				},
				"region": map[string]any{
					"type":        "string",
					"description": "Region for S3/GCS cache",
				},
				"endpoint": map[string]any{
					"type":        "string",
					"description": "Custom endpoint for S3 cache",
				},
				"insecure": map[string]any{
					"type":        "boolean",
					"description": "Use insecure connection for cache",
				},
				"storageAccount": map[string]any{
					"type":        "string",
					"description": "Storage account for Azure cache",
				},
				"containerName": map[string]any{
					"type":        "string",
					"description": "Container name for Azure cache",
				},
				"projectId": map[string]any{
					"type":        "string",
					"description": "Project ID for GCS cache",
				},
			}),
		),
	)
	s.server.AddTool(configTool, s.handleConfig)

	// Register resource listing tools
	listResourcesTool := mcp.NewTool("list-resources",
		mcp.WithDescription("List Kubernetes resources of a specific type (pods, deployments, services, nodes, etc.)"),
		mcp.WithString("resourceType",
			mcp.Required(),
			mcp.Description("Type of resource to list (e.g., pods, deployments, services, nodes, jobs, etc.)"),
		),
		mcp.WithString("namespace",
			mcp.Description("Namespace to list resources from (empty for all or cluster-scoped resources)"),
		),
		mcp.WithString("labelSelector",
			mcp.Description("Label selector to filter resources (e.g., 'app=myapp')"),
		),
	)
	s.server.AddTool(listResourcesTool, s.handleListResources)

	// Register get resource tool
	getResourceTool := mcp.NewTool("get-resource",
		mcp.WithDescription("Get detailed information about a specific Kubernetes resource"),
		mcp.WithString("resourceType",
			mcp.Required(),
			mcp.Description("Type of resource (e.g., pod, deployment, service)"),
		),
		mcp.WithString("name",
			mcp.Required(),
			mcp.Description("Name of the resource"),
		),
		mcp.WithString("namespace",
			mcp.Description("Namespace of the resource (required for namespaced resources)"),
		),
	)
	s.server.AddTool(getResourceTool, s.handleGetResource)

	// Register list namespaces tool
	listNamespacesTool := mcp.NewTool("list-namespaces",
		mcp.WithDescription("List all namespaces in the cluster"),
	)
	s.server.AddTool(listNamespacesTool, s.handleListNamespaces)

	// Register list events tool
	listEventsTool := mcp.NewTool("list-events",
		mcp.WithDescription("List Kubernetes events for debugging and troubleshooting"),
		mcp.WithString("namespace",
			mcp.Description("Namespace to list events from (empty for all namespaces)"),
		),
		mcp.WithString("involvedObjectName",
			mcp.Description("Filter events by involved object name (e.g., pod name)"),
		),
		mcp.WithString("involvedObjectKind",
			mcp.Description("Filter events by involved object kind (e.g., Pod, Deployment)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of events to return (default: 100)"),
		),
	)
	s.server.AddTool(listEventsTool, s.handleListEvents)

	// Register get logs tool
	getLogsTool := mcp.NewTool("get-logs",
		mcp.WithDescription("Get logs from a pod container"),
		mcp.WithString("podName",
			mcp.Required(),
			mcp.Description("Name of the pod"),
		),
		mcp.WithString("namespace",
			mcp.Required(),
			mcp.Description("Namespace of the pod"),
		),
		mcp.WithString("container",
			mcp.Description("Container name (if pod has multiple containers)"),
		),
		mcp.WithBoolean("previous",
			mcp.Description("Get logs from previous terminated container"),
		),
		mcp.WithNumber("tailLines",
			mcp.Description("Number of lines from the end of logs (default: 100)"),
		),
		mcp.WithNumber("sinceSeconds",
			mcp.Description("Return logs newer than this many seconds"),
		),
	)
	s.server.AddTool(getLogsTool, s.handleGetLogs)

	// Register filter management tools
	listFiltersTool := mcp.NewTool("list-filters",
		mcp.WithDescription("List all available and active analyzers/filters in k8sgpt"),
	)
	s.server.AddTool(listFiltersTool, s.handleListFilters)

	addFiltersTool := mcp.NewTool("add-filters",
		mcp.WithDescription("Add filters to enable specific analyzers"),
		mcp.WithArray("filters",
			mcp.Required(),
			mcp.Description("List of filter names to add (e.g., ['Pod', 'Service', 'Deployment'])"),
			mcp.WithStringItems(),
		),
	)
	s.server.AddTool(addFiltersTool, s.handleAddFilters)

	removeFiltersTool := mcp.NewTool("remove-filters",
		mcp.WithDescription("Remove filters to disable specific analyzers"),
		mcp.WithArray("filters",
			mcp.Required(),
			mcp.Description("List of filter names to remove"),
			mcp.WithStringItems(),
		),
	)
	s.server.AddTool(removeFiltersTool, s.handleRemoveFilters)

	// Register integration management tools
	listIntegrationsTool := mcp.NewTool("list-integrations",
		mcp.WithDescription("List available integrations (Prometheus, AWS, Keda, Kyverno, etc.)"),
	)
	s.server.AddTool(listIntegrationsTool, s.handleListIntegrations)

	healthScoreTool := mcp.NewTool("cluster-health-score",
		mcp.WithDescription("Compute and return the cluster health score (0-100) with grade and top contributors"),
		mcp.WithString("namespace",
			mcp.Description("Namespace to analyze (empty for all)"),
		),
	)
	s.server.AddTool(healthScoreTool, s.handleHealthScore)

	historyTool := mcp.NewTool("analysis-history",
		mcp.WithDescription("Query analysis result history: list runs, diff between runs, or view trends"),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("Action: list, diff, or trend"),
		),
		mcp.WithString("runId1",
			mcp.Description("First run ID for diff action"),
		),
		mcp.WithString("runId2",
			mcp.Description("Second run ID for diff action"),
		),
		mcp.WithString("since",
			mcp.Description("Duration for list/trend (e.g. 168h for 7 days)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Max results for list action (default 20)"),
		),
	)
	s.server.AddTool(historyTool, s.handleAnalysisHistory)

	policiesListTool := mcp.NewTool("remediation-policies",
		mcp.WithDescription("List configured remediation policies or test them against current cluster state"),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("Action: list or test"),
		),
		mcp.WithString("namespace",
			mcp.Description("Namespace for test action"),
		),
	)
	s.server.AddTool(policiesListTool, s.handleRemediationPolicies)

	policyAuditTool := mcp.NewTool("policy-audit",
		mcp.WithDescription("Query the policy audit log"),
		mcp.WithString("policyName",
			mcp.Description("Filter by policy name"),
		),
		mcp.WithString("since",
			mcp.Description("Duration filter (e.g. 168h)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Max entries (default 50)"),
		),
	)
	s.server.AddTool(policyAuditTool, s.handlePolicyAudit)

	return nil
}

// AnalyzeRequest represents the input parameters for the analyze tool
type AnalyzeRequest struct {
	Namespace       string   `json:"namespace,omitempty"`
	Backend         string   `json:"backend,omitempty"`
	Language        string   `json:"language,omitempty"`
	Filters         []string `json:"filters,omitempty"`
	LabelSelector   string   `json:"labelSelector,omitempty"`
	NoCache         bool     `json:"noCache,omitempty"`
	Explain         bool     `json:"explain,omitempty"`
	MaxConcurrency  int      `json:"maxConcurrency,omitempty"`
	WithDoc         bool     `json:"withDoc,omitempty"`
	InteractiveMode bool     `json:"interactiveMode,omitempty"`
	CustomHeaders   []string `json:"customHeaders,omitempty"`
	WithStats       bool     `json:"withStats,omitempty"`
	Anonymize       bool     `json:"anonymize,omitempty"`
}

// AnalyzeResponse represents the output of the analyze tool
type AnalyzeResponse struct {
	Results string `json:"results"`
}

// ClusterInfoRequest represents the input parameters for the cluster-info tool
type ClusterInfoRequest struct {
	// Empty struct as we don't need any input parameters
}

// ClusterInfoResponse represents the output of the cluster-info tool
type ClusterInfoResponse struct {
	Info string `json:"info"`
}

// ConfigRequest represents the input parameters for the config tool
type ConfigRequest struct {
	CustomAnalyzers []struct {
		Name       string `json:"name"`
		Connection struct {
			Url  string `json:"url"`
			Port int    `json:"port"`
		} `json:"connection"`
	} `json:"customAnalyzers,omitempty"`
	Cache struct {
		Type string `json:"type"`
		// S3 specific fields
		BucketName string `json:"bucketName,omitempty"`
		Region     string `json:"region,omitempty"`
		Endpoint   string `json:"endpoint,omitempty"`
		Insecure   bool   `json:"insecure,omitempty"`
		// Azure specific fields
		StorageAccount string `json:"storageAccount,omitempty"`
		ContainerName  string `json:"containerName,omitempty"`
		// GCS specific fields
		ProjectId string `json:"projectId,omitempty"`
	} `json:"cache,omitempty"`
}

// ConfigResponse represents the output of the config tool
type ConfigResponse struct {
	Status string `json:"status"`
}

// handleAnalyze handles the analyze tool
func (s *K8sGptMCPServer) handleAnalyze(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	var req AnalyzeRequest
	if err := request.BindArguments(&req); err != nil {
		return mcp.NewToolResultErrorf("Failed to parse request arguments: %v", err), nil
	}

	if req.Backend == "" {
		if s.aiProvider.Name != "" {
			req.Backend = s.aiProvider.Name
		} else {
			req.Backend = "openai" // fallback default
		}
	}

	// Get stored filters if not specified
	if len(req.Filters) == 0 {
		req.Filters = viper.GetStringSlice("active_filters")
	}

	// Validate MaxConcurrency to prevent excessive memory allocation
	req.MaxConcurrency = validateMaxConcurrency(req.MaxConcurrency)

	// Create a new analysis with the request parameters
	analysis, err := analysis.NewAnalysis(
		req.Backend,
		req.Language,
		req.Filters,
		req.Namespace,
		req.LabelSelector,
		req.NoCache,
		req.Explain,
		req.MaxConcurrency,
		req.WithDoc,
		req.InteractiveMode,
		req.CustomHeaders,
		req.WithStats,
	)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create analysis: %v", err), nil
	}
	defer analysis.Close()

	// Run the analysis
	analysis.RunAnalysis()
	if req.Explain {

		var output string
		err := analysis.GetAIResults(output, req.Anonymize)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to get results from AI: %v", err), nil
		}

		// Convert results to JSON string using PrintOutput
		outputBytes, err := analysis.PrintOutput("text")
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to convert results to string: %v", err), nil
		}
		plainText := stripANSI(string(outputBytes))
		return mcp.NewToolResultText(plainText), nil
	} else {
		// Get the output
		output, err := analysis.PrintOutput("json")
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to print output: %v", err), nil
		}
		return mcp.NewToolResultText(string(output)), nil
	}
}

// validateMaxConcurrency validates and bounds the MaxConcurrency parameter
func validateMaxConcurrency(maxConcurrency int) int {
	const maxAllowedConcurrency = 100
	if maxConcurrency <= 0 {
		return 10 // Default value if not set
	} else if maxConcurrency > maxAllowedConcurrency {
		return maxAllowedConcurrency // Cap at a reasonable maximum
	}
	return maxConcurrency
}

// handleClusterInfo handles the cluster-info tool
func (s *K8sGptMCPServer) handleClusterInfo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Create a new Kubernetes client
	client, err := kubernetes.NewClient("", "")
	if err != nil {
		return mcp.NewToolResultErrorf("failed to create Kubernetes client: %v", err), nil
	}

	// Get cluster info from the client
	version, err := client.Client.Discovery().ServerVersion()
	if err != nil {
		return mcp.NewToolResultErrorf("failed to get cluster version: %v", err), nil
	}

	info := fmt.Sprintf("Kubernetes %s", version.GitVersion)
	return mcp.NewToolResultText(info), nil
}

// handleConfig handles the config tool
func (s *K8sGptMCPServer) handleConfig(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse request arguments
	var req ConfigRequest
	if err := request.BindArguments(&req); err != nil {
		return mcp.NewToolResultErrorf("Failed to parse request arguments: %v", err), nil
	}

	// Create a new config handler
	handler := &config.Handler{}

	// Convert request to AddConfigRequest
	addConfigReq := &schemav1.AddConfigRequest{
		CustomAnalyzers: make([]*schemav1.CustomAnalyzer, 0),
	}

	// Add custom analyzers if present
	if len(req.CustomAnalyzers) > 0 {
		for _, ca := range req.CustomAnalyzers {
			addConfigReq.CustomAnalyzers = append(addConfigReq.CustomAnalyzers, &schemav1.CustomAnalyzer{
				Name: ca.Name,
				Connection: &schemav1.Connection{
					Url:  ca.Connection.Url,
					Port: fmt.Sprintf("%d", ca.Connection.Port),
				},
			})
		}
	}

	// Add cache configuration if present
	if req.Cache.Type != "" {
		cacheConfig := &schemav1.Cache{}
		switch req.Cache.Type {
		case "s3":
			cacheConfig.CacheType = &schemav1.Cache_S3Cache{
				S3Cache: &schemav1.S3Cache{
					BucketName: req.Cache.BucketName,
					Region:     req.Cache.Region,
					Endpoint:   req.Cache.Endpoint,
					Insecure:   req.Cache.Insecure,
				},
			}
		case "azure":
			cacheConfig.CacheType = &schemav1.Cache_AzureCache{
				AzureCache: &schemav1.AzureCache{
					StorageAccount: req.Cache.StorageAccount,
					ContainerName:  req.Cache.ContainerName,
				},
			}
		case "gcs":
			cacheConfig.CacheType = &schemav1.Cache_GcsCache{
				GcsCache: &schemav1.GCSCache{
					BucketName: req.Cache.BucketName,
					Region:     req.Cache.Region,
					ProjectId:  req.Cache.ProjectId,
				},
			}
		}
		addConfigReq.Cache = cacheConfig
	}

	// Apply the configuration using the shared function
	if err := handler.ApplyConfig(ctx, addConfigReq); err != nil {
		return mcp.NewToolResultErrorf("Failed to add config: %v", err), nil
	}

	return mcp.NewToolResultText("Successfully added configuration"), nil
}

// registerPrompts registers the prompts for the MCP server
func (s *K8sGptMCPServer) registerPrompts() error {
	// Register troubleshooting prompts
	podTroubleshootPrompt := mcp.NewPrompt("troubleshoot-pod",
		mcp.WithPromptDescription("Guide for troubleshooting pod issues in Kubernetes"),
		mcp.WithArgument("podName"),
		mcp.WithArgument("namespace"),
	)
	s.server.AddPrompt(podTroubleshootPrompt, s.getTroubleshootPodPrompt)

	deploymentTroubleshootPrompt := mcp.NewPrompt("troubleshoot-deployment",
		mcp.WithPromptDescription("Guide for troubleshooting deployment issues in Kubernetes"),
		mcp.WithArgument("deploymentName"),
		mcp.WithArgument("namespace"),
	)
	s.server.AddPrompt(deploymentTroubleshootPrompt, s.getTroubleshootDeploymentPrompt)

	generalTroubleshootPrompt := mcp.NewPrompt("troubleshoot-cluster",
		mcp.WithPromptDescription("General guide for troubleshooting Kubernetes cluster issues"),
	)
	s.server.AddPrompt(generalTroubleshootPrompt, s.getTroubleshootClusterPrompt)

	return nil
}

// registerResources registers the resources for the MCP server
func (s *K8sGptMCPServer) registerResources() error {
	clusterInfoResource := mcp.NewResource("cluster-info", "cluster-info",
		mcp.WithResourceDescription("Get information about the Kubernetes cluster"),
		mcp.WithMIMEType("application/json"),
	)
	s.server.AddResource(clusterInfoResource, s.getClusterInfo)

	namespacesResource := mcp.NewResource("namespaces", "namespaces",
		mcp.WithResourceDescription("List all namespaces in the cluster"),
		mcp.WithMIMEType("application/json"),
	)
	s.server.AddResource(namespacesResource, s.getNamespacesResource)

	activeFiltersResource := mcp.NewResource("active-filters", "active-filters",
		mcp.WithResourceDescription("Get currently active analyzers/filters"),
		mcp.WithMIMEType("application/json"),
	)
	s.server.AddResource(activeFiltersResource, s.getActiveFiltersResource)

	healthScoreResource := mcp.NewResource("cluster-health-score", "cluster-health-score",
		mcp.WithResourceDescription("Current cluster health score"),
		mcp.WithMIMEType("application/json"),
	)
	s.server.AddResource(healthScoreResource, s.getHealthScoreResource)

	return nil
}

func (s *K8sGptMCPServer) getClusterInfo(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	// Create a new Kubernetes client
	client, err := kubernetes.NewClient("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	// Get cluster info from the client
	version, err := client.Client.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster version: %v", err)
	}

	data, err := json.Marshal(map[string]string{
		"version":    version.String(),
		"platform":   version.Platform,
		"gitVersion": version.GitVersion,
	})
	if err != nil {
		return []mcp.ResourceContents{
			&mcp.TextResourceContents{
				URI:      "cluster-info",
				MIMEType: "text/plain",
				Text:     "Failed to marshal cluster info",
			},
		}, nil
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      "cluster-info",
			MIMEType: "application/json",
			Text:     string(data),
		},
	}, nil
}

func (s *K8sGptMCPServer) getNamespacesResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	client, err := kubernetes.NewClient("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	namespaces, err := client.Client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %v", err)
	}

	// Extract just the namespace names
	names := make([]string, 0, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		names = append(names, ns.Name)
	}

	data, err := json.Marshal(map[string]interface{}{
		"count":      len(names),
		"namespaces": names,
	})
	if err != nil {
		return []mcp.ResourceContents{
			&mcp.TextResourceContents{
				URI:      "namespaces",
				MIMEType: "text/plain",
				Text:     "Failed to marshal namespaces",
			},
		}, nil
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      "namespaces",
			MIMEType: "application/json",
			Text:     string(data),
		},
	}, nil
}

func (s *K8sGptMCPServer) getActiveFiltersResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	activeFilters := viper.GetStringSlice("active_filters")

	data, err := json.Marshal(map[string]interface{}{
		"activeFilters": activeFilters,
		"count":         len(activeFilters),
	})
	if err != nil {
		return []mcp.ResourceContents{
			&mcp.TextResourceContents{
				URI:      "active-filters",
				MIMEType: "text/plain",
				Text:     "Failed to marshal active filters",
			},
		}, nil
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      "active-filters",
			MIMEType: "application/json",
			Text:     string(data),
		},
	}, nil
}

// handleHealthScore handles the cluster-health-score tool
func (s *K8sGptMCPServer) handleHealthScore(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Namespace string `json:"namespace,omitempty"`
	}
	_ = request.BindArguments(&req)
	a, err := analysis.NewAnalysis("", "", nil, req.Namespace, "", true, false, 10, false, false, nil, false)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create analysis: %v", err), nil
	}
	defer a.Close()
	a.RunAnalysis()
	a.ComputeScore()
	if a.Score == nil {
		return mcp.NewToolResultErrorf("Score computation failed"), nil
	}
	data, err := json.Marshal(a.Score)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to marshal score: %v", err), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// getHealthScoreResource handles the cluster-health-score resource
func (s *K8sGptMCPServer) getHealthScoreResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	a, err := analysis.NewAnalysis("", "", nil, "", "", true, false, 10, false, false, nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create analysis: %v", err)
	}
	defer a.Close()
	a.RunAnalysis()
	a.ComputeScore()
	data, _ := json.Marshal(a.Score)
	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      "cluster-health-score",
			MIMEType: "application/json",
			Text:     string(data),
		},
	}, nil
}

// handleAnalysisHistory handles the analysis-history tool
func (s *K8sGptMCPServer) handleAnalysisHistory(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	action, _ := args["action"].(string)

	resultStore, err := store.GetDefaultStore()
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to open store: %v", err), nil
	}
	defer resultStore.Close()

	switch action {
	case "list":
		opts := store.ListOpts{Limit: 20}
		if limitVal, ok := args["limit"].(float64); ok {
			opts.Limit = int(limitVal)
		}
		if sinceStr, ok := args["since"].(string); ok && sinceStr != "" {
			if d, err := time.ParseDuration(sinceStr); err == nil {
				opts.Since = time.Now().Add(-d)
			}
		}
		runs, err := resultStore.ListRuns(opts)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to list runs: %v", err), nil
		}
		data, _ := json.MarshalIndent(runs, "", "  ")
		return mcp.NewToolResultText(string(data)), nil

	case "diff":
		runID1, _ := args["runId1"].(string)
		runID2, _ := args["runId2"].(string)
		if runID1 == "" || runID2 == "" {
			return mcp.NewToolResultErrorf("Both runId1 and runId2 are required for diff"), nil
		}
		diff, err := resultStore.Diff(runID1, runID2)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to diff: %v", err), nil
		}
		data, _ := json.MarshalIndent(diff, "", "  ")
		return mcp.NewToolResultText(string(data)), nil

	case "trend":
		opts := store.TrendOpts{}
		if sinceStr, ok := args["since"].(string); ok && sinceStr != "" {
			if d, err := time.ParseDuration(sinceStr); err == nil {
				opts.Since = time.Now().Add(-d)
			}
		}
		trend, err := resultStore.Trend(opts)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to get trend: %v", err), nil
		}
		data, _ := json.MarshalIndent(trend, "", "  ")
		return mcp.NewToolResultText(string(data)), nil

	default:
		return mcp.NewToolResultErrorf("Unknown action %q. Use: list, diff, trend", action), nil
	}
}

// handleRemediationPolicies handles the remediation-policies tool
func (s *K8sGptMCPServer) handleRemediationPolicies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	action, _ := args["action"].(string)

	switch action {
	case "list":
		policies := policy.LoadPolicies()
		data, err := json.MarshalIndent(policies, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to marshal policies: %v", err), nil
		}
		return mcp.NewToolResultText(string(data)), nil

	case "test":
		namespace, _ := args["namespace"].(string)
		a, err := analysis.NewAnalysis("", "", nil, namespace, "", true, false, 10, false, false, nil, false)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to create analysis: %v", err), nil
		}
		defer a.Close()
		a.RunAnalysis()

		policies := policy.LoadPolicies()
		engine := &policy.Engine{
			Policies:   policies,
			PolicyMode: "dry-run",
		}
		evalResults := engine.Evaluate(a.Results, namespace)
		data, err := json.MarshalIndent(evalResults, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to marshal eval results: %v", err), nil
		}
		return mcp.NewToolResultText(string(data)), nil

	default:
		return mcp.NewToolResultErrorf("Unknown action %q. Use: list, test", action), nil
	}
}

// handlePolicyAudit handles the policy-audit tool
func (s *K8sGptMCPServer) handlePolicyAudit(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	resultStore, err := store.GetDefaultStore()
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to open store: %v", err), nil
	}
	defer resultStore.Close()

	opts := policy.AuditOpts{Limit: 50}

	if policyName, ok := args["policyName"].(string); ok && policyName != "" {
		opts.PolicyName = policyName
	}
	if sinceStr, ok := args["since"].(string); ok && sinceStr != "" {
		if d, err := time.ParseDuration(sinceStr); err == nil {
			opts.Since = time.Now().Add(-d)
		}
	}
	if limitVal, ok := args["limit"].(float64); ok && limitVal > 0 {
		opts.Limit = int(limitVal)
	}

	entries, err := policy.QueryAuditLog(resultStore.DB(), opts)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to query audit log: %v", err), nil
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to marshal audit entries: %v", err), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// Close closes the MCP server and releases resources
func (s *K8sGptMCPServer) Close() error {
	return nil
}

// zapLoggerAdapter adapts zap.Logger to the interface expected by mark3labs/mcp-go
type zapLoggerAdapter struct {
	logger *zap.Logger
}

func (z *zapLoggerAdapter) Infof(format string, v ...any) {
	z.logger.Info(fmt.Sprintf(format, v...))
}

func (z *zapLoggerAdapter) Errorf(format string, v ...any) {
	z.logger.Error(fmt.Sprintf(format, v...))
}

// stripANSI removes ANSI escape sequences from a string
func stripANSI(input string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(input, "")
}
