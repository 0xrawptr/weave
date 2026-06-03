package artifact

import (
	"context"
	"encoding/json"
)

// Input is the common input wrapper for all artifacts.
type Input struct {
	Target string          `json:"target"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// Output is the common output wrapper for all artifacts.
type Output struct {
	Artifact string          `json:"artifact"`
	Target   string          `json:"target"`
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`      // lightweight, for workflow
	FullData json.RawMessage `json:"full_data,omitempty"` // complete, for persist
}

// InputSchema describes the expected input format for an artifact.
type InputSchema struct {
	Fields []SchemaField `json:"fields"`
}

// OutputSchema describes the output format for an artifact.
type OutputSchema struct {
	Fields []SchemaField `json:"fields"`
}

// SchemaField describes a single field in input/output.
type SchemaField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// Descriptor describes runtime behavior beyond basic JSON schemas. The planner
// uses this to decide whether an artifact is safe and useful for a candidate action.
type Descriptor struct {
	Name          string   `json:"name"`
	Consumes      []string `json:"consumes"`
	Produces      []string `json:"produces"`
	Passive       bool     `json:"passive"`
	TouchesTarget bool     `json:"touches_target"`
	Risk          string   `json:"risk"` // low, medium, high
	Description   string   `json:"description,omitempty"`
}

// URLResolver resolves a scan target to a list of web URLs discovered
// by a previous stage (typically gogo). The artifact queries the resolver
// when no explicit URLs are provided in its input.
type URLResolver func(ctx context.Context, target string) ([]string, error)

// TagResolver resolves a scan target to a list of fingerprint tags for template filtering.
type TagResolver func(ctx context.Context, target string) ([]string, error)

// Artifact is the standardized interface for all prism artifacts.
type Artifact interface {
	Name() string
	InputSchema() InputSchema
	OutputSchema() OutputSchema
	Execute(ctx context.Context, input Input) (Output, error)
	Close() error
}

type DescribedArtifact interface {
	Descriptor() Descriptor
}
