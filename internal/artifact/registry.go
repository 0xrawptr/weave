package artifact

import (
	"fmt"
	"sync"
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

// Close closes all registered artifacts.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.artifacts {
		a.Close()
	}
}
