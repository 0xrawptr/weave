package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xrawptr/weave/internal/api"
	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"

	sdkclient "github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/provider"
	"go.temporal.io/sdk/client"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()

	pg, err := data.NewPostgresStore(ctx, data.PostgresConfig{
		Host:     cfg.Postgres.Host,
		Port:     cfg.Postgres.Port,
		User:     cfg.Postgres.User,
		Password: cfg.Postgres.Password,
		Database: cfg.Postgres.Database,
		SSLMode:  cfg.Postgres.SSLMode,
	})
	if err != nil {
		log.Printf("WARNING: PostgreSQL unavailable: %v (data persistence disabled)", err)
	}

	neo, err := data.NewNeo4jStore(ctx, data.Neo4jConfig{
		URI:      cfg.Neo4j.URI,
		User:     cfg.Neo4j.User,
		Password: cfg.Neo4j.Password,
	})
	if err != nil {
		log.Printf("WARNING: Neo4j unavailable: %v (graph queries disabled)", err)
	}

	rds := data.NewRedisStore(data.RedisConfig{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := rds.Ping(ctx); err != nil {
		log.Printf("WARNING: Redis unavailable: %v (dedup disabled)", err)
	}

	repo := data.NewRepository(pg, neo, rds)

	// Initialize artifact registry from SDK client (shared provider + auto DI).
	sdkCli := sdkclient.New(sdkclient.WithProvider(provider.NewEmbedProvider()))
	reg, err := artifact.NewRegistryFromClient(sdkCli)
	if err != nil {
		log.Fatalf("artifact init: %v", err)
	}
	log.Printf("registered %d artifacts", len(reg.List()))

	temporalClient, err := client.Dial(client.Options{
		HostPort:  cfg.Temporal.Host + ":" + formatPort(cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Printf("WARNING: Temporal unavailable: %v (workflow execution disabled)", err)
	}

	server := api.NewServer(cfg, reg, repo, temporalClient)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		server.Shutdown(ctx)
		reg.Close()
		sdkCli.Close()
		if temporalClient != nil {
			temporalClient.Close()
		}
	}()

	log.Println("weave server starting...")
	if err := server.Run(); err != nil {
		log.Fatalf("server run: %v", err)
	}
}

func formatPort(port int) string {
	return fmt.Sprintf("%d", port)
}
