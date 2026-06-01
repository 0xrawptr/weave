package artifact

import (
	"fmt"
	"sync"

	sdkclient "github.com/chainreactors/sdk/client"
)

// Registry manages all registered artifacts.
type Registry struct {
	mu        sync.RWMutex
	artifacts map[string]Artifact
}

func NewRegistry() *Registry {
	return &Registry{
		artifacts: make(map[string]Artifact),
	}
}

// Register adds an artifact to the registry.
func (r *Registry) Register(a Artifact) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.artifacts[a.Name()] = a
}

// Get returns an artifact by name.
func (r *Registry) Get(name string) (Artifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.artifacts[name]
	if !ok {
		return nil, fmt.Errorf("artifact %q not found", name)
	}
	return a, nil
}

// List returns all registered artifact names and schemas.
func (r *Registry) List() []ArtifactInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	infos := make([]ArtifactInfo, 0, len(r.artifacts))
	for _, a := range r.artifacts {
		infos = append(infos, ArtifactInfo{
			Name:         a.Name(),
			InputSchema:  a.InputSchema(),
			OutputSchema: a.OutputSchema(),
		})
	}
	return infos
}

// ArtifactInfo is a lightweight descriptor of a registered artifact.
type ArtifactInfo struct {
	Name         string       `json:"name"`
	InputSchema  InputSchema  `json:"input_schema"`
	OutputSchema OutputSchema `json:"output_schema"`
}

// NewRegistryFromClient creates a registry pre-populated with all engines
// managed by an SDK client. cdncheck is also registered independently.
func NewRegistryFromClient(c *sdkclient.Client) (*Registry, error) {
	gogoEngine, err := c.Gogo()
	if err != nil {
		return nil, fmt.Errorf("gogo: %w", err)
	}
	fingersEngine, err := c.Fingers()
	if err != nil {
		return nil, fmt.Errorf("fingers: %w", err)
	}
	neutronEngine, err := c.Neutron()
	if err != nil {
		return nil, fmt.Errorf("neutron: %w", err)
	}
	sprayEngine, err := c.Spray()
	if err != nil {
		return nil, fmt.Errorf("spray: %w", err)
	}
	zombieEngine, err := c.Zombie()
	if err != nil {
		return nil, fmt.Errorf("zombie: %w", err)
	}
	cdncheckEngine, err := NewCdncheckArtifact()
	if err != nil {
		return nil, fmt.Errorf("cdncheck: %w", err)
	}

	reg := NewRegistry()
	reg.Register(NewGogoArtifactFromEngine(gogoEngine))
	reg.Register(NewFingersArtifactFromEngine(fingersEngine))
	reg.Register(NewNeutronArtifactFromEngine(neutronEngine))
	reg.Register(NewSprayArtifactFromEngine(sprayEngine))
	reg.Register(NewZombieArtifactFromEngine(zombieEngine))
	reg.Register(cdncheckEngine)
	return reg, nil
}

// Close closes all registered artifacts.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.artifacts {
		a.Close()
	}
}
