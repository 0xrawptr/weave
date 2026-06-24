package app

import (
	"context"
	"testing"

	"github.com/0xrawptr/weave/internal/etl"
)

type noopLoader struct{}

func (noopLoader) Save(context.Context, *etl.ExtractResult) error {
	return nil
}

func TestArtifactRuntimeDefinitionsBuildPipelines(t *testing.T) {
	seen := map[string]bool{}
	for _, def := range artifactRuntimeDefinitions {
		if def.Name == "" {
			t.Fatalf("artifact runtime definition has empty name")
		}
		if seen[def.Name] {
			t.Fatalf("duplicate artifact runtime definition: %s", def.Name)
		}
		seen[def.Name] = true
		if def.Build == nil {
			t.Fatalf("%s missing artifact builder", def.Name)
		}
		if def.Extractor == nil {
			t.Fatalf("%s missing extractor builder", def.Name)
		}
	}

	pipelines := buildPipelines(noopLoader{}, nil)
	if len(pipelines) != len(artifactRuntimeDefinitions) {
		t.Fatalf("pipelines = %d, want %d", len(pipelines), len(artifactRuntimeDefinitions))
	}
	for _, def := range artifactRuntimeDefinitions {
		if pipelines[def.Name] == nil {
			t.Fatalf("missing pipeline for %s", def.Name)
		}
	}
}
