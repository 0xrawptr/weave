package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/0xrawptr/weave/internal/workflow"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

// StartWorkflowRequest is the request body for starting a new workflow.
type StartWorkflowRequest struct {
	Type   string                 `json:"type"`   // "domain", "ip", "company"
	Input  map[string]interface{} `json:"input"`  // workflow-specific input
	Target string                 `json:"target"` // shorthand for target
}

func generateWorkflowID(wfType string) string {
	return fmt.Sprintf("%s-%d", wfType, time.Now().UnixNano())
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

	ctx := context.Background()
	workflowID := generateWorkflowID(req.Type)

	var run client.WorkflowRun
	opts := client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: s.cfg.Temporal.TaskQueue,
	}

	switch req.Type {
	case "domain":
		domain := req.Target
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
		ip := req.Target
		ports := "top1000"
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
		ip := req.Target
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
		company := req.Target
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported workflow type: " + req.Type})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"workflow_id": run.GetID(),
		"run_id":      run.GetRunID(),
		"type":        req.Type,
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
