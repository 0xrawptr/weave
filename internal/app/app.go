package app

import (
	"context"
	"log"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/etl"
	"github.com/0xrawptr/weave/internal/knowledge"
	sdkclient "github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/provider"
)

type Pipelines struct {
	Gogo     *etl.Pipeline
	Fingers  *etl.Pipeline
	Neutron  *etl.Pipeline
	Spray    *etl.Pipeline
	Zombie   *etl.Pipeline
	Cdncheck *etl.Pipeline
	Nuclei   *etl.Pipeline
}

type App struct {
	Config    *config.Config
	Repo      *data.Repository
	SDK       *sdkclient.Client
	Registry  *artifact.Registry
	Knowledge *knowledge.Index
	Enricher  etl.Enricher
	Pipelines Pipelines
}

func New(ctx context.Context, cfg *config.Config) (*App, error) {
	repo := initRepository(ctx, cfg)

	sdkCli := sdkclient.New(sdkclient.WithProvider(provider.NewEmbedProvider()), sdkclient.WithIndex(nil))
	reg, err := artifact.NewRegistryFromClient(sdkCli)
	if err != nil {
		sdkCli.Close()
		repo.Close()
		return nil, err
	}

	loader := etl.MakeLoader(repo)
	kb, knowledgeEnricher := initKnowledge(cfg)
	enricher := etl.NewMultiEnricher(etl.NewAssociationEnricher(sdkCli), knowledgeEnricher)

	runtime := &App{
		Config:    cfg,
		Repo:      repo,
		SDK:       sdkCli,
		Registry:  reg,
		Knowledge: kb,
		Enricher:  enricher,
		Pipelines: Pipelines{
			Gogo:     etl.NewPipeline(&etl.GogoExtractor{}, loader).WithEnricher(enricher),
			Fingers:  etl.NewPipeline(&etl.FingersExtractor{}, loader).WithEnricher(enricher),
			Neutron:  etl.NewPipeline(&etl.NeutronExtractor{}, loader),
			Spray:    etl.NewPipeline(&etl.SprayExtractor{}, loader),
			Zombie:   etl.NewPipeline(&etl.ZombieExtractor{}, loader),
			Cdncheck: etl.NewPipeline(&etl.CdncheckExtractor{}, loader),
			Nuclei:   etl.NewPipeline(&etl.NucleiExtractor{}, loader),
		},
	}
	runtime.WireResolvers()
	return runtime, nil
}

func (a *App) WireResolvers() {
	if a == nil || a.Repo == nil || a.Repo.Postgres == nil || a.Registry == nil {
		return
	}
	urlResolver := artifact.URLResolver(func(ctx context.Context, target string) ([]string, error) {
		return a.Repo.GetWebURLs(ctx, target)
	})
	if artifactInstance, err := a.Registry.Get("fingers"); err == nil {
		artifactInstance.(*artifact.FingersArtifact).SetURLResolver(urlResolver)
	}
	if artifactInstance, err := a.Registry.Get("neutron"); err == nil {
		artifactInstance.(*artifact.NeutronArtifact).SetURLResolver(urlResolver)
	}
	if artifactInstance, err := a.Registry.Get("nuclei"); err == nil {
		nucleiArtifact := artifactInstance.(*artifact.NucleiArtifact)
		nucleiArtifact.SetURLResolver(urlResolver)
		nucleiArtifact.SetIDResolver(func(ctx context.Context, target string) ([]string, error) {
			return a.Repo.GetTemplateIDs(ctx, target)
		})
		nucleiArtifact.SetTagResolver(func(ctx context.Context, target string) ([]string, error) {
			tags, err := a.Repo.GetTags(ctx, target)
			if err != nil || len(tags) > 0 {
				return tags, err
			}
			return a.Repo.GetFingerprints(ctx, target)
		})
	}
}

func (a *App) Close() {
	if a == nil {
		return
	}
	if a.Registry != nil {
		a.Registry.Close()
	}
	if a.SDK != nil {
		a.SDK.Close()
	}
	if a.Repo != nil {
		a.Repo.Close()
	}
}

func initRepository(ctx context.Context, cfg *config.Config) *data.Repository {
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

	var rds *data.RedisStore
	redisStore := data.NewRedisStore(data.RedisConfig{
		Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB,
	})
	if err := redisStore.Ping(ctx); err != nil {
		log.Printf("WARNING: Redis unavailable: %v", err)
		_ = redisStore.Close()
	} else {
		rds = redisStore
	}

	return data.NewRepository(pg, neo, rds)
}

func initKnowledge(cfg *config.Config) (*knowledge.Index, etl.Enricher) {
	kb, err := knowledge.Load(knowledge.Options{
		NucleiTemplatesPath:   cfg.Knowledge.NucleiTemplatesPath,
		ProductAliasesPath:    cfg.Knowledge.ProductAliasesPath,
		KEVPath:               cfg.Knowledge.KEVPath,
		EPSSPath:              cfg.Knowledge.EPSSPath,
		VulnrichmentPath:      cfg.Knowledge.VulnrichmentPath,
		MaxTemplatesPerLookup: cfg.Knowledge.MaxTemplatesPerLookup,
	})
	if err != nil {
		log.Printf("WARNING: local knowledge base disabled: %v", err)
		return nil, nil
	}
	if kb == nil || kb.Len() == 0 {
		return kb, nil
	}
	log.Printf("local knowledge base loaded: templates=%d cves=%d", kb.Len(), kb.CVELen())
	return kb, etl.NewKnowledgeEnricher(kb)
}
