package api

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

// Server holds all dependencies for the API server.
type Server struct {
	cfg      *config.Config
	router   *gin.Engine
	registry *artifact.Registry
	repo     *data.Repository
	planner  *planner.Planner
	temporal client.Client

	httpServer *http.Server
}

// NewServer creates a new API server with all dependencies.
func NewServer(cfg *config.Config, registry *artifact.Registry, repo *data.Repository, temporalClient client.Client) *Server {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	s := &Server{
		cfg:      cfg,
		router:   gin.Default(),
		registry: registry,
		repo:     repo,
		planner:  planner.New(repo),
		temporal: temporalClient,
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	v1 := s.router.Group("/api/v1")
	{
		// Artifact endpoints
		v1.GET("/artifacts", s.ListArtifacts)
		v1.GET("/artifacts/:name", s.GetArtifact)

		// Campaign endpoints
		v1.POST("/campaigns", s.CreateCampaign)
		v1.GET("/campaigns", s.ListCampaigns)
		v1.GET("/campaigns/:id", s.GetCampaign)
		v1.POST("/campaigns/:id/status", s.UpdateCampaignStatus)

		// Workflow endpoints
		v1.POST("/workflows", s.StartWorkflow)
		v1.GET("/workflows/:id", s.GetWorkflow)
		v1.DELETE("/workflows/:id", s.CancelWorkflow)

		// Result endpoints
		v1.GET("/results", s.ListResults)
		v1.GET("/events", s.ListEvents)
		v1.GET("/stats", s.ListArtifactStats)
		v1.GET("/results/graph", s.QueryGraph)
		v1.GET("/results/:id", s.GetResult)
		v1.GET("/results/:id/events", s.ListResultEvents)
		v1.POST("/results/:id/status", s.UpdateResultStatus)
		v1.GET("/batches", s.ListBatches)
		v1.GET("/batches/:id/chunks", s.ListBatchChunks)
		v1.POST("/batches/:id/retry_failed", s.RetryFailedBatchChunks)
		v1.POST("/batches/:id/resume_scheduler", s.ResumeBatchScheduler)
		v1.GET("/work-items", s.ListWorkItems)
		v1.GET("/work-items/summary", s.WorkItemSummary)
		v1.POST("/work-items/retry", s.RetryWorkItems)
		v1.POST("/work-items/pause", s.PauseWorkItems)
		v1.POST("/work-items/resume", s.ResumeWorkItems)
		v1.POST("/work-items/recover-stale", s.RecoverStaleWorkItems)
		v1.GET("/stats/summary", s.ArtifactStatsSummary)

		// Planner endpoints
		v1.GET("/plan", s.PlanTarget)
		v1.GET("/plan/dag", s.PlanDAGTarget)
		v1.GET("/actions", s.ListActions)
		v1.POST("/actions", s.StartAction)
	}
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.cfg.Server.Port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	log.Printf("API server listening on %s", addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
