package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/workflow"

	sdkclient "github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/provider"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	sdkworker "go.temporal.io/sdk/worker"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()

	pg, pgErr := data.NewPostgresStore(ctx, data.PostgresConfig{
		Host: cfg.Postgres.Host, Port: cfg.Postgres.Port,
		User: cfg.Postgres.User, Password: cfg.Postgres.Password,
		Database: cfg.Postgres.Database, SSLMode: cfg.Postgres.SSLMode,
	})
	if pgErr != nil {
		log.Printf("WARNING: PostgreSQL unavailable: %v", pgErr)
	}

	neo, neoErr := data.NewNeo4jStore(ctx, data.Neo4jConfig{
		URI: cfg.Neo4j.URI, User: cfg.Neo4j.User, Password: cfg.Neo4j.Password,
	})
	if neoErr != nil {
		log.Printf("WARNING: Neo4j unavailable: %v", neoErr)
	}

	rds := data.NewRedisStore(data.RedisConfig{
		Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB,
	})
	if err := rds.Ping(ctx); err != nil {
		log.Printf("WARNING: Redis unavailable: %v", err)
	}

	repo := data.NewRepository(pg, neo, rds)

	var persistHook artifact.PersistHook
	var dedupHook artifact.DedupHook
	var markDoneHook artifact.MarkDoneHook

	if repo.Postgres != nil && repo.Neo4j != nil {
		persistHook = func(ctx context.Context, result *artifact.ActivityResult) error {
			return repo.PersistActivityResult(ctx, result.Artifact, result.Target, result.Data)
		}
		log.Println("persist hook enabled (PostgreSQL + Neo4j)")
	} else {
		log.Println("persist disabled (PostgreSQL or Neo4j unavailable)")
	}
	if repo.Redis != nil {
		dedupHook = func(ctx context.Context, target, artifactName string, input []byte) (bool, error) {
			return repo.CheckDuplicate(ctx, target, artifactName, input)
		}
		markDoneHook = func(ctx context.Context, target, artifactName string, input []byte) error {
			return repo.MarkDuplicate(ctx, target, artifactName, input, 24*time.Hour)
		}
	}

	c, err := client.Dial(client.Options{
		HostPort:  fmt.Sprintf("%s:%d", cfg.Temporal.Host, cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("temporal client: %v", err)
	}
	defer c.Close()

	sdkCli := sdkclient.New(sdkclient.WithProvider(provider.NewEmbedProvider()))
	reg, regErr := artifact.NewRegistryFromClient(sdkCli)
	if regErr != nil {
		log.Fatalf("artifact init: %v", regErr)
	}

	w := sdkworker.New(c, cfg.Temporal.TaskQueue, sdkworker.Options{})

	for _, info := range reg.List() {
		a, _ := reg.Get(info.Name)
		w.RegisterActivityWithOptions(
			artifact.NewActivityFunc(a, persistHook, dedupHook, markDoneHook),
			activity.RegisterOptions{Name: info.Name},
		)
		log.Printf("registered activity: %s", info.Name)
	}

	w.RegisterWorkflow(workflow.DomainWorkflow)
	w.RegisterWorkflow(workflow.IPWorkflow)
	w.RegisterWorkflow(workflow.CompanyWorkflow)
	w.RegisterWorkflow(workflow.PortScanWorkflow)
	log.Println("registered workflows: domain, ip, company, portscan")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down worker...")
		w.Stop()
		reg.Close()
		sdkCli.Close()
		repo.Close()
	}()

	log.Printf("worker started on task queue %q", cfg.Temporal.TaskQueue)
	if err := w.Run(sdkworker.InterruptCh()); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}
