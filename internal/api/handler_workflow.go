package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/workflow"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

// StartWorkflowRequest is the request body for starting a new workflow.
type StartWorkflowRequest struct {
	Type   string                 `json:"type"`   // "auto", "planned", "domain", "ip", "portscan", "batch_portscan", "company"
	Input  map[string]interface{} `json:"input"`  // workflow-specific input
	Target string                 `json:"target"` // shorthand for target
}

func generateWorkflowID(wfType string) string {
	return fmt.Sprintf("%s-%d", wfType, time.Now().UnixNano())
}

// resolveTarget parses a raw target string and returns the workflow type,
// cleaned target, and default ports.
func resolveTarget(raw string) (wfType, target, ports string) {
	raw = strings.TrimSpace(raw)

	// IP:port format — e.g. "1.1.1.1:789" (port must be numeric to avoid
	// treating "https://example.com" as IP:port).
	if host, port, err := net.SplitHostPort(raw); err == nil && isNumeric(port) {
		return "ip", host, port
	}

	// CIDR format — e.g. "1.1.1.0/24" (only if the part after / is a number)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") && strings.Contains(raw, "/") {
		afterSlash := raw[strings.LastIndex(raw, "/")+1:]
		if isNumeric(afterSlash) {
			return "ip", raw, "top1000"
		}
		return "", raw, "" // URL path, not CIDR
	}

	// Plain IP — e.g. "1.1.1.1"
	if net.ParseIP(raw) != nil {
		return "ip", raw, "top1000"
	}

	// Domain — may have http/https prefix.
	if strings.Contains(raw, ".") && !strings.Contains(raw, " ") {
		clean := raw
		if strings.HasPrefix(clean, "https://") {
			clean = clean[8:]
		} else if strings.HasPrefix(clean, "http://") {
			clean = clean[7:]
		}
		if !strings.Contains(clean, "/") {
			return "domain", raw, ""
		}
		// Has a path — can't determine type automatically.
		return "", raw, ""
	}

	return "", raw, ""
}

// StartWorkflow creates and starts a new workflow execution.
func (s *Server) StartWorkflow(c *gin.Context) {
	var req StartWorkflowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}

	// Auto-detect workflow type from target format
	detectedType := req.Type
	detectedTarget := req.Target
	detectedPorts := "top1000"
	if req.Type == "auto" || req.Type == "" {
		detectedType, detectedTarget, detectedPorts = resolveTarget(req.Target)
		if detectedType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unable to determine target type: " + req.Target})
			return
		}
	}

	ctx := context.Background()
	workflowID := generateWorkflowID(detectedType)

	var run client.WorkflowRun
	opts := client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: s.cfg.Temporal.TaskQueue,
	}

	switch detectedType {
	case "planned":
		target := detectedTarget
		if target == "" {
			target = req.Target
		}
		if t, ok := req.Input["target"].(string); ok && t != "" {
			target = t
		}
		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target is required for planned workflow"})
			return
		}
		detectedTarget = target
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.PlannedWorkflow,
			workflow.PlannedWorkflowInput{
				Target:        target,
				MaxIterations: inputInt(req.Input, "max_iterations"),
				MaxActions:    inputInt(req.Input, "max_actions"),
			},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	case "domain":
		domain := detectedTarget
		if d, ok := req.Input["domain"].(string); ok {
			domain = d
		}
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.DomainWorkflow,
			workflow.DomainWorkflowInput{Domain: domain},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	case "ip":
		ip := detectedTarget
		ports := detectedPorts
		if i, ok := req.Input["ip"].(string); ok {
			ip = i
		}
		if p, ok := req.Input["ports"].(string); ok {
			ports = p
		}
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.IPWorkflow,
			workflow.IPWorkflowInput{IP: ip, Ports: ports},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	case "portscan":
		ip := detectedTarget
		ports := "1-65535"
		if i, ok := req.Input["ip"].(string); ok {
			ip = i
		}
		if p, ok := req.Input["ports"].(string); ok {
			ports = p
		}
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.PortScanWorkflow,
			workflow.PortScanInput{IP: ip, Ports: ports},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	case "batch_portscan":
		targets := inputStringSlice(req.Input, "targets")
		if len(targets) == 0 {
			targets = splitTargetList(req.Target)
		}
		if len(targets) == 0 {
			targets = splitTargetList(detectedTarget)
		}
		if len(targets) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "targets are required for batch_portscan workflow"})
			return
		}
		ports := "top1000"
		if p, ok := req.Input["ports"].(string); ok && p != "" {
			ports = p
		}
		detectedTarget = fmt.Sprintf("%d targets", len(targets))
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.BatchPortScanWorkflow,
			workflow.BatchPortScanInput{
				Targets:        targets,
				Ports:          ports,
				MaxConcurrency: inputInt(req.Input, "max_concurrency"),
				ChunkPrefix:    inputInt(req.Input, "chunk_prefix"),
			},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	case "company":
		company := detectedTarget
		var domains []string
		if cn, ok := req.Input["company"].(string); ok {
			company = cn
		}
		if ds, ok := req.Input["domains"].([]interface{}); ok {
			for _, d := range ds {
				if ds, ok := d.(string); ok {
					domains = append(domains, ds)
				}
			}
		}
		var err error
		run, err = s.temporal.ExecuteWorkflow(ctx, opts,
			workflow.CompanyWorkflow,
			workflow.CompanyWorkflowInput{Company: company, Domains: domains},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported workflow type: " + detectedType})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"workflow_id": run.GetID(),
		"run_id":      run.GetRunID(),
		"type":        detectedType,
		"target":      detectedTarget,
	})
}

// GetWorkflow returns the status of a workflow execution.
func (s *Server) GetWorkflow(c *gin.Context) {
	id := c.Param("id")

	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}

	ctx := context.Background()

	desc, err := s.temporal.DescribeWorkflowExecution(ctx, id, "")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"workflow_id":   desc.WorkflowExecutionInfo.Execution.WorkflowId,
		"run_id":        desc.WorkflowExecutionInfo.Execution.RunId,
		"status":        desc.WorkflowExecutionInfo.Status.String(),
		"workflow_type": desc.WorkflowExecutionInfo.Type.Name,
		"start_time":    desc.WorkflowExecutionInfo.StartTime,
	})
}

// CancelWorkflow cancels a running workflow.
func (s *Server) CancelWorkflow(c *gin.Context) {
	id := c.Param("id")

	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}

	ctx := context.Background()

	if err := s.temporal.CancelWorkflow(ctx, id, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func inputInt(input map[string]interface{}, key string) int {
	if input == nil {
		return 0
	}
	switch value := input[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case jsonNumber:
		i, _ := value.Int64()
		return int(i)
	default:
		return 0
	}
}

func inputStringSlice(input map[string]interface{}, key string) []string {
	if input == nil {
		return nil
	}
	switch value := input[key].(type) {
	case []string:
		return cleanStringSlice(value)
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return cleanStringSlice(out)
	case string:
		return splitTargetList(value)
	default:
		return nil
	}
}

func splitTargetList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	return cleanStringSlice(parts)
}

func cleanStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

type jsonNumber interface {
	Int64() (int64, error)
}
