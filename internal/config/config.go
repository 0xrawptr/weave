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
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"`
}

type TemporalConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Namespace string `yaml:"namespace"`
	TaskQueue string `yaml:"task_queue"`
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
	Neutron ArtifactOpts `yaml:"neutron"`
	Zombie  ArtifactOpts `yaml:"zombie"`
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
		c.Temporal.TaskQueue = "prism-task-queue"
	}
}
