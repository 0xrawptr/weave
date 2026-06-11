package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Temporal  TemporalConfig  `yaml:"temporal"`
	Postgres  PostgresConfig  `yaml:"postgres"`
	Neo4j     Neo4jConfig     `yaml:"neo4j"`
	Redis     RedisConfig     `yaml:"redis"`
	Artifacts ArtifactsConfig `yaml:"artifacts"`
	Knowledge KnowledgeConfig `yaml:"knowledge"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"`
}

type TemporalConfig struct {
	Host      string        `yaml:"host"`
	Port      int           `yaml:"port"`
	Namespace string        `yaml:"namespace"`
	TaskQueue string        `yaml:"task_queue"`
	Workers   WorkersConfig `yaml:"workers"`
}

type WorkersConfig struct {
	Control         WorkerConfig            `yaml:"control"`
	DefaultArtifact WorkerConfig            `yaml:"default_artifact"`
	Artifacts       map[string]WorkerConfig `yaml:"artifacts"`
}

type WorkerConfig struct {
	MaxConcurrentActivityTasks       int           `yaml:"max_concurrent_activity_tasks"`
	MaxConcurrentWorkflowTasks       int           `yaml:"max_concurrent_workflow_tasks"`
	MaxConcurrentActivityTaskPollers int           `yaml:"max_concurrent_activity_task_pollers"`
	MaxConcurrentWorkflowTaskPollers int           `yaml:"max_concurrent_workflow_task_pollers"`
	WorkerActivitiesPerSecond        float64       `yaml:"worker_activities_per_second"`
	TaskQueueActivitiesPerSecond     float64       `yaml:"task_queue_activities_per_second"`
	WorkerStopTimeout                time.Duration `yaml:"worker_stop_timeout"`
}

type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"sslmode"`
}

type Neo4jConfig struct {
	URI      string `yaml:"uri"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type ArtifactsConfig struct {
	Gogo    ArtifactOpts `yaml:"gogo"`
	Spray   ArtifactOpts `yaml:"spray"`
	Fingers ArtifactOpts `yaml:"fingers"`
	DNSX    ArtifactOpts `yaml:"dnsx"`
	Neutron ArtifactOpts `yaml:"neutron"`
	Zombie  ArtifactOpts `yaml:"zombie"`
}

type KnowledgeConfig struct {
	NucleiTemplatesPath   string `yaml:"nuclei_templates_path"`
	ProductAliasesPath    string `yaml:"product_aliases_path"`
	KEVPath               string `yaml:"kev_path"`
	EPSSPath              string `yaml:"epss_path"`
	VulnrichmentPath      string `yaml:"vulnrichment_path"`
	MaxTemplatesPerLookup int    `yaml:"max_templates_per_lookup"`
}

type ArtifactOpts struct {
	Threads  int           `yaml:"threads,omitempty"`
	Capacity int           `yaml:"capacity,omitempty"`
	Timeout  time.Duration `yaml:"timeout"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = []byte(os.ExpandEnv(string(data)))

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.setDefaults()
	return cfg, nil
}

func (c *Config) setDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.Mode == "" {
		c.Server.Mode = "debug"
	}
	if c.Temporal.Host == "" {
		c.Temporal.Host = "localhost"
	}
	if c.Temporal.Port == 0 {
		c.Temporal.Port = 7233
	}
	if c.Temporal.Namespace == "" {
		c.Temporal.Namespace = "default"
	}
	if c.Temporal.TaskQueue == "" {
		c.Temporal.TaskQueue = "weave-task-queue"
	}
	if c.Temporal.Workers.Artifacts == nil {
		c.Temporal.Workers.Artifacts = map[string]WorkerConfig{}
	}
	c.setWorkerDefaults()
}

func (c *Config) setWorkerDefaults() {
	if c.Temporal.Workers.Control.MaxConcurrentWorkflowTasks == 0 {
		c.Temporal.Workers.Control.MaxConcurrentWorkflowTasks = 32
	}
	if c.Temporal.Workers.Control.MaxConcurrentActivityTasks == 0 {
		c.Temporal.Workers.Control.MaxConcurrentActivityTasks = 32
	}
	if c.Temporal.Workers.Control.MaxConcurrentWorkflowTaskPollers == 0 {
		c.Temporal.Workers.Control.MaxConcurrentWorkflowTaskPollers = 4
	}
	if c.Temporal.Workers.Control.MaxConcurrentActivityTaskPollers == 0 {
		c.Temporal.Workers.Control.MaxConcurrentActivityTaskPollers = 4
	}
	if c.Temporal.Workers.Control.WorkerStopTimeout == 0 {
		c.Temporal.Workers.Control.WorkerStopTimeout = 30 * time.Second
	}

	if c.Temporal.Workers.DefaultArtifact.MaxConcurrentActivityTasks == 0 {
		c.Temporal.Workers.DefaultArtifact.MaxConcurrentActivityTasks = 4
	}
	if c.Temporal.Workers.DefaultArtifact.MaxConcurrentActivityTaskPollers == 0 {
		c.Temporal.Workers.DefaultArtifact.MaxConcurrentActivityTaskPollers = 2
	}
	if c.Temporal.Workers.DefaultArtifact.WorkerStopTimeout == 0 {
		c.Temporal.Workers.DefaultArtifact.WorkerStopTimeout = 30 * time.Second
	}

	defaults := map[string]WorkerConfig{
		"gogo": {
			MaxConcurrentActivityTasks:       4,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"spray": {
			MaxConcurrentActivityTasks:       6,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"nuclei": {
			MaxConcurrentActivityTasks:       3,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"neutron": {
			MaxConcurrentActivityTasks:       2,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"zombie": {
			MaxConcurrentActivityTasks:       1,
			MaxConcurrentActivityTaskPollers: 1,
			WorkerStopTimeout:                30 * time.Second,
		},
		"fingers": {
			MaxConcurrentActivityTasks:       8,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"cdncheck": {
			MaxConcurrentActivityTasks:       8,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
		"dnsx": {
			MaxConcurrentActivityTasks:       8,
			MaxConcurrentActivityTaskPollers: 2,
			WorkerStopTimeout:                30 * time.Second,
		},
	}
	for artifactName, defaultsForArtifact := range defaults {
		current := c.Temporal.Workers.Artifacts[artifactName]
		c.Temporal.Workers.Artifacts[artifactName] = mergeWorkerConfig(current, defaultsForArtifact)
	}
}

func mergeWorkerConfig(primary WorkerConfig, fallback WorkerConfig) WorkerConfig {
	if primary.MaxConcurrentActivityTasks == 0 {
		primary.MaxConcurrentActivityTasks = fallback.MaxConcurrentActivityTasks
	}
	if primary.MaxConcurrentWorkflowTasks == 0 {
		primary.MaxConcurrentWorkflowTasks = fallback.MaxConcurrentWorkflowTasks
	}
	if primary.MaxConcurrentActivityTaskPollers == 0 {
		primary.MaxConcurrentActivityTaskPollers = fallback.MaxConcurrentActivityTaskPollers
	}
	if primary.MaxConcurrentWorkflowTaskPollers == 0 {
		primary.MaxConcurrentWorkflowTaskPollers = fallback.MaxConcurrentWorkflowTaskPollers
	}
	if primary.WorkerActivitiesPerSecond == 0 {
		primary.WorkerActivitiesPerSecond = fallback.WorkerActivitiesPerSecond
	}
	if primary.TaskQueueActivitiesPerSecond == 0 {
		primary.TaskQueueActivitiesPerSecond = fallback.TaskQueueActivitiesPerSecond
	}
	if primary.WorkerStopTimeout == 0 {
		primary.WorkerStopTimeout = fallback.WorkerStopTimeout
	}
	return primary
}

func (c *Config) ArtifactWorkerConfig(artifactName string) WorkerConfig {
	base := c.Temporal.Workers.DefaultArtifact
	if c.Temporal.Workers.Artifacts == nil {
		return base
	}
	return mergeWorkerConfig(c.Temporal.Workers.Artifacts[artifactName], base)
}
