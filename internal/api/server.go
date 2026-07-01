package api

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/0xrawptr/weave/internal/api/middleware"
	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

// Server holds all dependencies for the API server.
type Server struct {
	cfg       *config.Config
	router    *gin.Engine
	registry  *artifact.Registry
	repo      *data.Repository
	planner   *planner.Planner
	temporal  client.Client
	authStore middleware.TokenStore

	httpServer *http.Server
}

// NewServer creates a new API server with all dependencies.
func NewServer(cfg *config.Config, registry *artifact.Registry, repo *data.Repository, temporalClient client.Client) *Server {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	authCfg := middleware.AuthConfig{
		Enabled: cfg.Auth.Enabled,
		APIKey:  cfg.Auth.APIKey,
	}
	authCfg.Admin.Username = cfg.Auth.Admin.Username
	authCfg.Admin.Password = cfg.Auth.Admin.Password

	authStore := middleware.NewAuthStore(authCfg)

	s := &Server{
		cfg:       cfg,
		router:    gin.Default(),
		registry:  registry,
		repo:      repo,
		planner:   planner.New(repo),
		temporal:  temporalClient,
		authStore: authStore,
	}

	s.setupRoutes(authCfg)
	return s
}

func (s *Server) setupRoutes(authCfg middleware.AuthConfig) {
	// Public routes (no auth required)
	v1 := s.router.Group("/api/v1")
	{
		// Auth
		v1.POST("/auth/login", middleware.LoginHandler(authCfg, s.authStore))

		// Health (public)
		v1.GET("/dashboard/health", s.DashboardHealth)
	}

	// Protected routes
	protected := s.router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(authCfg, s.authStore))
	{
		// Artifact endpoints
		protected.GET("/artifacts", s.ListArtifacts)
		protected.GET("/artifacts/:name", s.GetArtifact)

		// Campaign endpoints
		protected.POST("/campaigns", s.CreateCampaign)
		protected.GET("/campaigns", s.ListCampaigns)
		protected.GET("/campaigns/:id", s.GetCampaign)
		protected.GET("/campaigns/:id/runtime", s.GetCampaignRuntime)
		protected.POST("/campaigns/:id/status", s.UpdateCampaignStatus)

		// Result endpoints
		protected.GET("/results", s.ListResults)
		protected.GET("/events", s.ListEvents)
		protected.GET("/stats", s.ListArtifactStats)
		protected.GET("/results/graph", s.QueryGraph)
		protected.GET("/results/:id", s.GetResult)
		protected.GET("/results/:id/events", s.ListResultEvents)
		protected.POST("/results/:id/status", s.UpdateResultStatus)
		protected.GET("/batches", s.ListBatches)
		protected.POST("/batches", s.StartBatch)
		protected.GET("/batches/:id/chunks", s.ListBatchChunks)
		protected.POST("/batches/:id/stop", s.StopBatch)
		// Policy endpoints
		protected.POST("/policies", s.CreatePolicy)
		protected.GET("/policies", s.ListPolicies)
		protected.GET("/policies/:id", s.GetPolicy)
		protected.PUT("/policies/:id", s.UpdatePolicy)
		// Integration endpoints
		protected.POST("/integrations/icp", s.ICPQuery)
		protected.POST("/integrations/fofa/search", s.FofaSearch)
		protected.POST("/integrations/github/search", s.GitHubSearch)
		protected.POST("/assets/enrich-geo", s.EnrichGeoIP)

		protected.GET("/dicts", s.ListDicts)
		protected.GET("/dicts/:name", s.GetDict)
		protected.POST("/dicts/:name", s.AppendDict)
		protected.DELETE("/dicts/:name", s.DeleteDict)

		// Fingerprints & PoCs
		protected.GET("/fingerprints", s.ListFingerprints)
		protected.POST("/fingerprints", s.CreateFingerprint)
		protected.DELETE("/fingerprints/:id", s.DeleteFingerprint)
		protected.POST("/monitors", s.CreateMonitor)
		protected.GET("/monitors", s.ListMonitors)
		protected.POST("/monitors/:id/pause", s.PauseMonitor)
		protected.POST("/monitors/:id/resume", s.ResumeMonitor)
		protected.DELETE("/monitors/:id", s.DeleteMonitor)

		protected.GET("/pocs", s.ListPoCs)
		protected.POST("/pocs/sync", s.SyncPoCs)

		protected.DELETE("/policies/:id", s.DeletePolicy)

		protected.GET("/batches/:id/export", s.ExportBatch)
		protected.DELETE("/batches/:id", s.DeleteBatch)
		protected.POST("/batches/:id/resume_scheduler", s.ResumeBatchScheduler)
		protected.GET("/work-items", s.ListWorkItems)
		protected.GET("/work-items/summary", s.WorkItemSummary)
		protected.POST("/work-items/retry", s.RetryWorkItems)
		protected.POST("/work-items/pause", s.PauseWorkItems)
		protected.POST("/work-items/resume", s.ResumeWorkItems)
		protected.POST("/work-items/recover", s.RecoverWorkItems)
		protected.GET("/stats/summary", s.ArtifactStatsSummary)

		// Dashboard
		protected.GET("/dashboard/stats", s.DashboardStats)
		protected.GET("/dashboard/trend", s.DashboardTrend)

		// Planner endpoints
		protected.GET("/plan", s.PlanTarget)
		protected.GET("/actions", s.ListActions)
		protected.POST("/actions", s.StartAction)
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
