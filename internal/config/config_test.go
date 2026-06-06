package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("WEAVE_TEST_NUCLEI_PATH", "/tmp/nuclei-templates")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
knowledge:
  nuclei_templates_path: ${WEAVE_TEST_NUCLEI_PATH}
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Knowledge.NucleiTemplatesPath != "/tmp/nuclei-templates" {
		t.Fatalf("NucleiTemplatesPath = %q", cfg.Knowledge.NucleiTemplatesPath)
	}
}

func TestLoadSetsWorkerDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`temporal: {}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Temporal.Workers.Control.MaxConcurrentWorkflowTasks != 32 {
		t.Fatalf("control workflow concurrency = %d", cfg.Temporal.Workers.Control.MaxConcurrentWorkflowTasks)
	}
	if cfg.Temporal.TaskQueue != "weave-task-queue" {
		t.Fatalf("task queue = %q", cfg.Temporal.TaskQueue)
	}
	if cfg.ArtifactWorkerConfig("gogo").MaxConcurrentActivityTasks != 4 {
		t.Fatalf("gogo activity concurrency = %d", cfg.ArtifactWorkerConfig("gogo").MaxConcurrentActivityTasks)
	}
	if cfg.ArtifactWorkerConfig("spray").MaxConcurrentActivityTasks != 2 {
		t.Fatalf("spray activity concurrency = %d", cfg.ArtifactWorkerConfig("spray").MaxConcurrentActivityTasks)
	}
	if cfg.ArtifactWorkerConfig("unknown").MaxConcurrentActivityTasks != 4 {
		t.Fatalf("unknown artifact activity concurrency = %d", cfg.ArtifactWorkerConfig("unknown").MaxConcurrentActivityTasks)
	}
}

func TestLoadAllowsArtifactWorkerOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
temporal:
  workers:
    default_artifact:
      max_concurrent_activity_tasks: 5
    artifacts:
      spray:
        max_concurrent_activity_tasks: 7
        worker_activities_per_second: 1.5
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	spray := cfg.ArtifactWorkerConfig("spray")
	if spray.MaxConcurrentActivityTasks != 7 {
		t.Fatalf("spray activity concurrency = %d", spray.MaxConcurrentActivityTasks)
	}
	if spray.WorkerActivitiesPerSecond != 1.5 {
		t.Fatalf("spray worker rate = %f", spray.WorkerActivitiesPerSecond)
	}
	unknown := cfg.ArtifactWorkerConfig("unknown")
	if unknown.MaxConcurrentActivityTasks != 5 {
		t.Fatalf("unknown artifact activity concurrency = %d", unknown.MaxConcurrentActivityTasks)
	}
}
