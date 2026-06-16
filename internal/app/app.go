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
	sdkgogo "github.com/chainreactors/sdk/gogo"
	sdkneutron "github.com/chainreactors/sdk/neutron"
	"github.com/chainreactors/sdk/pkg/association"
	"github.com/chainreactors/sdk/pkg/cyberhub"
	"github.com/chainreactors/sdk/pkg/provider"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
	sdkproton "github.com/chainreactors/sdk/proton"
	sdkspray "github.com/chainreactors/sdk/spray"
	sdkzombie "github.com/chainreactors/sdk/zombie"
	spraypkg "github.com/chainreactors/spray/pkg"
)

type Pipelines struct {
	Gogo     *etl.Pipeline
	Fingers  *etl.Pipeline
	Neutron  *etl.Pipeline
	Spray    *etl.Pipeline
	Zombie   *etl.Pipeline
	Proton   *etl.Pipeline
	Cdncheck *etl.Pipeline
	DNSX     *etl.Pipeline
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

	sdkCli := buildSDKClient(cfg)
	reg, err := artifact.NewRegistryFromClient(sdkCli)
	if err != nil {
		sdkCli.Close()
		repo.Close()
		return nil, err
	}
	configureArtifactDefaults(reg, cfg)

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
			Spray:    etl.NewPipeline(&etl.SprayExtractor{}, loader).WithEnricher(enricher),
			Zombie:   etl.NewPipeline(&etl.ZombieExtractor{}, loader),
			Proton:   etl.NewPipeline(&etl.ProtonExtractor{}, loader),
			Cdncheck: etl.NewPipeline(&etl.CdncheckExtractor{}, loader),
			DNSX:     etl.NewPipeline(&etl.DNSXExtractor{}, loader),
			Nuclei:   etl.NewPipeline(&etl.NucleiExtractor{}, loader),
		},
	}
	runtime.WireResolvers()
	return runtime, nil
}

func configureArtifactDefaults(reg *artifact.Registry, cfg *config.Config) {
	if reg == nil || cfg == nil {
		return
	}
	if cfg.Artifacts.Gogo.Threads > 0 {
		if a, err := reg.Get("gogo"); err == nil {
			if gogoArtifact, ok := a.(*artifact.GogoArtifact); ok {
				gogoArtifact.SetThreads(cfg.Artifacts.Gogo.Threads)
			}
		}
	}
	if cfg.Artifacts.Spray.Threads > 0 {
		if a, err := reg.Get("spray"); err == nil {
			if sprayArtifact, ok := a.(*artifact.SprayArtifact); ok {
				sprayArtifact.SetDefaultThreads(cfg.Artifacts.Spray.Threads)
			}
		}
	}
}

func buildSDKClient(cfg *config.Config) *sdkclient.Client {
	opts := []sdkclient.Option{
		sdkclient.WithProvider(buildProviders(cfg)...),
		sdkclient.WithIndex(&association.IndexOptions{
			MetadataKeys: []string{"product", "vendor", "service"},
		}),
	}
	if cfg == nil {
		return sdkclient.New(opts...)
	}

	if cfg.SDK.Proxy != "" {
		opts = append(opts, sdkclient.WithProxy(cfg.SDK.Proxy))
	}

	gogoCfg := sdkgogo.NewConfig()
	if capacity := sdkCapacity("gogo", cfg.Artifacts.Gogo.Capacity); capacity > 0 {
		gogoCfg.WithCapacity(capacity)
		opts = append(opts, sdkclient.WithGogoConfig(gogoCfg))
	}

	sprayCfg := sdkspray.NewConfig().WithMatchDetail().WithResourceProvider(spraypkg.LoadEmbeddedConfig)
	if capacity := sdkCapacity("spray", cfg.Artifacts.Spray.Capacity); capacity > 0 {
		sprayCfg.WithCapacity(capacity)
	}
	opts = append(opts, sdkclient.WithSprayConfig(sprayCfg))

	neutronCfg := sdkneutron.NewConfig()
	if capacity := sdkCapacity("neutron", cfg.Artifacts.Neutron.Capacity); capacity > 0 {
		neutronCfg.Capacity = capacity
		opts = append(opts, sdkclient.WithNeutronConfig(neutronCfg))
	}

	zombieCfg := sdkzombie.NewConfig()
	if capacity := sdkCapacity("zombie", cfg.Artifacts.Zombie.Capacity); capacity > 0 {
		zombieCfg.WithCapacity(capacity)
		opts = append(opts, sdkclient.WithZombieConfig(zombieCfg))
	}

	protonCfg := sdkproton.NewConfig()
	if capacity := sdkCapacity("proton", cfg.Artifacts.Proton.Capacity); capacity > 0 {
		protonCfg.WithCapacity(capacity)
	}
	if len(cfg.Artifacts.Proton.TemplatePaths) > 0 {
		protonCfg.WithTemplatePaths(cfg.Artifacts.Proton.TemplatePaths...)
	}
	if len(cfg.Artifacts.Proton.Tags) > 0 {
		protonCfg.WithTags(cfg.Artifacts.Proton.Tags...)
	}
	if len(cfg.Artifacts.Proton.ExcludeTags) > 0 {
		protonCfg.WithExcludeTags(cfg.Artifacts.Proton.ExcludeTags...)
	}
	if len(cfg.Artifacts.Proton.IDs) > 0 {
		protonCfg.WithIDs(cfg.Artifacts.Proton.IDs...)
	}
	if len(cfg.Artifacts.Proton.ExcludeIDs) > 0 {
		protonCfg.WithExcludeIDs(cfg.Artifacts.Proton.ExcludeIDs...)
	}
	if cfg.Artifacts.Proton.TextOnly != nil {
		protonCfg.WithTextOnly(*cfg.Artifacts.Proton.TextOnly)
	}
	opts = append(opts, sdkclient.WithProtonConfig(protonCfg))

	return sdkclient.New(opts...)
}

func sdkCapacity(artifact string, override int) int {
	if override > 0 {
		return override
	}
	return data.DefaultSDKCapacityForArtifact(artifact)
}

func buildProviders(cfg *config.Config) []sdktypes.Provider {
	providers := []sdktypes.Provider{provider.NewEmbedProvider()}
	if cfg == nil {
		return providers
	}
	if fp := cfg.SDK.File; fp != nil && (fp.FingersPath != "" || fp.POCsPath != "") {
		providers = append(providers, provider.NewFileProvider(fp.FingersPath, fp.POCsPath))
	}
	if up := cfg.SDK.URL; up != nil && (up.FingersURL != "" || up.POCsURL != "") {
		providers = append(providers, provider.NewURLProvider(up.FingersURL, up.POCsURL))
	}
	if ch := cfg.SDK.CyberHub; ch != nil && ch.Endpoint != "" {
		p := cyberhub.NewProvider(ch.Endpoint, ch.APIKey)
		if ch.Draft {
			p.WithFilter(sdktypes.NewExportFilter().WithDraft(true))
		}
		providers = append(providers, p)
	}
	return providers
}

func (a *App) SyncSDKCapacity(capacities []data.SchedulerCapacity) map[string]int {
	out := map[string]int{}
	if a == nil || a.Registry == nil {
		return out
	}
	for _, capacity := range capacities {
		if capacity.Artifact == "" || capacity.EffectiveCapacity <= 0 {
			continue
		}
		artifactInstance, err := a.Registry.Get(capacity.Artifact)
		if err != nil {
			continue
		}
		resizable, ok := artifactInstance.(artifact.SDKCapacityResizable)
		if !ok {
			continue
		}
		total := resizable.ResizeSDKCapacity(capacity.EffectiveCapacity)
		if total > 0 {
			out[capacity.Artifact] = total
		}
	}
	return out
}

func (a *App) SyncSDKCapacityWithLog(capacities []data.SchedulerCapacity) {
	totals := a.SyncSDKCapacity(capacities)
	for artifactName, total := range totals {
		log.Printf("sdk capacity resized: artifact=%s total=%d", artifactName, total)
	}
}

func (a *App) WireResolvers() {
	if a == nil || a.Repo == nil || a.Repo.Postgres == nil || a.Registry == nil {
		return
	}
	urlResolver := artifact.URLResolver(func(ctx context.Context, target string) ([]string, error) {
		return a.Repo.GetWebURLsInCampaign(ctx, target, artifact.CampaignIDFromContext(ctx))
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
			return a.Repo.GetTemplateIDsInCampaign(ctx, target, artifact.CampaignIDFromContext(ctx))
		})
		nucleiArtifact.SetTagResolver(func(ctx context.Context, target string) ([]string, error) {
			campaignID := artifact.CampaignIDFromContext(ctx)
			tags, err := a.Repo.GetTagsInCampaign(ctx, target, campaignID)
			if err != nil || len(tags) > 0 {
				return tags, err
			}
			return a.Repo.GetFingerprintsInCampaign(ctx, target, campaignID)
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
