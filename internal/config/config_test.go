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
