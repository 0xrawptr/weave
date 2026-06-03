package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net"
	"strings"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/etl"
	"github.com/0xrawptr/weave/internal/workflow"

	sdkclient "github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/provider"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	sdkworker "go.temporal.io/sdk/worker"
)

func targetType(raw string) string {
	if strings.Contains(raw, "/") {
		return "cidr"
	}
	if net.ParseIP(raw) != nil {
		return "ip"
	}
	if strings.Contains(raw, ".") {
		return "domain"
	}
	return "unknown"
}

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

	if repo.Postgres != nil {
		persistHook = func(ctx context.Context, result *artifact.ActivityResult) error {
			return repo.PersistActivityResult(ctx, result.Artifact, result.Target, result.Data)
		}
		log.Println("persist hook enabled (PostgreSQL)")
	} else {
		log.Println("persist disabled (PostgreSQL unavailable)")
	}
	if repo.Redis != nil {
		dedupHook = func(ctx context.Context, target, artifactName string, input []byte) (bool, error) {
			if artifactName != "gogo" {
				return false, nil
			}
			return repo.CheckDuplicate(ctx, target, artifactName, input)
		}
		markDoneHook = func(ctx context.Context, target, artifactName string, input []byte) error {
			return repo.MarkDuplicate(ctx, target, artifactName, input, 8*time.Hour)
		}
	}

	loader := etl.MakeLoader(repo)
	gogoETL := etl.NewPipeline(&etl.GogoExtractor{}, loader)
	fingersETL := etl.NewPipeline(&etl.FingersExtractor{}, loader)
	nucleiETL := etl.NewPipeline(&etl.NucleiExtractor{}, loader)

	c, err := client.Dial(client.Options{
		HostPort:  fmt.Sprintf("%s:%d", cfg.Temporal.Host, cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("temporal client: %v", err)
	}
	defer c.Close()

	sdkCli := sdkclient.New(sdkclient.WithProvider(provider.NewEmbedProvider()), sdkclient.WithIndex(nil))
	reg, regErr := artifact.NewRegistryFromClient(sdkCli)
	if regErr != nil {
		log.Fatalf("artifact init: %v", regErr)
	}

	if repo.Postgres != nil {
		urlResolver := artifact.URLResolver(func(ctx context.Context, target string) ([]string, error) {
			return repo.GetWebURLs(ctx, target)
		})
		if a, err := reg.Get("fingers"); err == nil {
			a.(*artifact.FingersArtifact).SetURLResolver(urlResolver)
		}
		if a, err := reg.Get("neutron"); err == nil {
			a.(*artifact.NeutronArtifact).SetURLResolver(urlResolver)
		}
		if a, err := reg.Get("nuclei"); err == nil {
			a.(*artifact.NucleiArtifact).SetURLResolver(urlResolver)
			a.(*artifact.NucleiArtifact).SetTagResolver(func(ctx context.Context, target string) ([]string, error) {
				return repo.GetFingerprints(ctx, target)
			})
		}
	}
	if a, err := reg.Get("gogo"); err == nil {
		a.(*artifact.GogoArtifact).SetResultHandler(func(ctx context.Context, target string, result *sdktypes.GOGOResult) {
			raw, _ := json.Marshal(result)
			// Raw event lake — per-result.
			_ = repo.SaveRawEvent(ctx, &data.RawEvent{
				ID: fmt.Sprintf("gogo-stream-%d", time.Now().UnixNano()),
				Artifact: "gogo", TargetID: target, TargetType: targetType(target),
				WorkflowID: "", Data: raw,
			})
			// ETL — per-result entities.
			wrapped, _ := json.Marshal(map[string]interface{}{"results": []json.RawMessage{raw}})
			if err := gogoETL.Process(ctx, target, wrapped); err != nil {
				log.Printf("WARNING: gogo streaming ETL failed: %v", err)
			}
		})
	}

	w := sdkworker.New(c, cfg.Temporal.TaskQueue, sdkworker.Options{})

	for _, info := range reg.List() {
		a, _ := reg.Get(info.Name)
		w.RegisterActivityWithOptions(
			artifact.NewActivityFunc(a, persistHook, dedupHook, markDoneHook,
				func(ctx context.Context, artifactName, target, workflowID string, eventData []byte) {
					if err := repo.SaveRawEvent(ctx, &data.RawEvent{
						ID:         fmt.Sprintf("%s-%d", workflowID, time.Now().UnixNano()),
						Artifact:   artifactName,
						TargetID:   target,
						TargetType: targetType(target),
						WorkflowID: workflowID,
						Data:       eventData,
					}); err != nil {
						log.Printf("WARNING: raw event save failed for %s: %v", artifactName, err)
					}
					var etlErr error
					switch artifactName {
					case "gogo":
						etlErr = gogoETL.Process(ctx, target, eventData)
					case "fingers":
						etlErr = fingersETL.Process(ctx, target, eventData)
					case "nuclei":
						etlErr = nucleiETL.Process(ctx, target, eventData)
					}
					if etlErr != nil {
						log.Printf("WARNING: ETL failed for %s: %v", artifactName, etlErr)
					}
				},
			),
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
