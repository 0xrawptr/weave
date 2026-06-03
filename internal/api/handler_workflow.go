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
	Type   string                 `json:"type"`   // "auto", "domain", "ip", "portscan", "company"
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

	// IP:port format — e.g. "1.1.1.1:789"
	if host, port, err := net.SplitHostPort(raw); err == nil {
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

	// Looks like a domain (has a dot, no spaces, no path)
	if strings.Contains(raw, ".") && !strings.Contains(raw, " ") && !strings.Contains(raw, "/") {
		return "domain", raw, ""
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
