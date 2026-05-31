package api

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

// Server holds all dependencies for the API server.
type Server struct {
	cfg      *config.Config
	router   *gin.Engine
	registry *artifact.Registry
	repo     *data.Repository
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

		// Workflow endpoints
		v1.POST("/workflows", s.StartWorkflow)
		v1.GET("/workflows/:id", s.GetWorkflow)
		v1.DELETE("/workflows/:id", s.CancelWorkflow)

		// Result endpoints
		v1.GET("/results", s.ListResults)
		v1.GET("/results/:id", s.GetResult)
		v1.GET("/results/graph", s.QueryGraph)
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
