package app

import (
	"fmt"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/etl"
	sdkclient "github.com/chainreactors/sdk/client"
)

type ArtifactRuntimeDefinition struct {
	Name        string
	Build       func(*sdkclient.Client) (artifact.Artifact, error)
	Extractor   func() etl.Extractor
	UseEnricher bool
}

var artifactRuntimeDefinitions = []ArtifactRuntimeDefinition{
	{
		Name: "gogo",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Gogo()
			if err != nil {
				return nil, err
			}
			return artifact.NewGogoArtifactFromEngine(engine), nil
		},
		Extractor:   func() etl.Extractor { return &etl.GogoExtractor{} },
		UseEnricher: true,
	},
	{
		Name: "fingers",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Fingers()
			if err != nil {
				return nil, err
			}
			return artifact.NewFingersArtifactFromEngine(engine), nil
		},
		Extractor:   func() etl.Extractor { return &etl.FingersExtractor{} },
		UseEnricher: true,
	},
	{
		Name: "neutron",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Neutron()
			if err != nil {
				return nil, err
			}
			return artifact.NewNeutronArtifactFromEngine(engine), nil
		},
		Extractor: func() etl.Extractor { return &etl.NeutronExtractor{} },
	},
	{
		Name: "spray",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Spray()
			if err != nil {
				return nil, err
			}
			return artifact.NewSprayArtifactFromEngine(engine), nil
		},
		Extractor:   func() etl.Extractor { return &etl.SprayExtractor{} },
		UseEnricher: true,
	},
	{
		Name: "zombie",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Zombie()
			if err != nil {
				return nil, err
			}
			return artifact.NewZombieArtifactFromEngine(engine), nil
		},
		Extractor: func() etl.Extractor { return &etl.ZombieExtractor{} },
	},
	{
		Name: "proton",
		Build: func(c *sdkclient.Client) (artifact.Artifact, error) {
			engine, err := c.Proton()
			if err != nil {
				return nil, err
			}
			return artifact.NewProtonArtifactFromEngine(engine), nil
		},
		Extractor: func() etl.Extractor { return &etl.ProtonExtractor{} },
	},
	{
		Name: "cdncheck",
		Build: func(*sdkclient.Client) (artifact.Artifact, error) {
			return artifact.NewCdncheckArtifact()
		},
		Extractor: func() etl.Extractor { return &etl.CdncheckExtractor{} },
	},
	{
		Name: "dnsx",
		Build: func(*sdkclient.Client) (artifact.Artifact, error) {
			return artifact.NewDNSXArtifact()
		},
		Extractor: func() etl.Extractor { return &etl.DNSXExtractor{} },
	},
	{
		Name: "nuclei",
		Build: func(*sdkclient.Client) (artifact.Artifact, error) {
			return artifact.NewNucleiArtifact()
		},
		Extractor: func() etl.Extractor { return &etl.NucleiExtractor{} },
	},
}

func buildRegistry(c *sdkclient.Client) (*artifact.Registry, error) {
	reg := artifact.NewRegistry()
	for _, def := range artifactRuntimeDefinitions {
		instance, err := def.Build(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", def.Name, err)
		}
		reg.Register(instance)
	}
	return reg, nil
}

func buildPipelines(loader etl.Loader, enricher etl.Enricher) map[string]*etl.Pipeline {
	pipelines := make(map[string]*etl.Pipeline, len(artifactRuntimeDefinitions))
	for _, def := range artifactRuntimeDefinitions {
		pipeline := etl.NewPipeline(def.Extractor(), loader)
		if def.UseEnricher {
			pipeline.WithEnricher(enricher)
		}
		pipelines[def.Name] = pipeline
	}
	return pipelines
}
