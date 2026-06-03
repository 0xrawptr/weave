package etl

import "context"

// Extractor reads raw artifact output and produces normalized entities + relations.
type Extractor interface {
	Extract(ctx context.Context, target string, data []byte) (*ExtractResult, error)
}

// Loader writes entities and relations to storage.
type Loader interface {
	Save(ctx context.Context, result *ExtractResult) error
}

// Pipeline runs extract → load for a single artifact result.
type Pipeline struct {
	extractor Extractor
	loader    Loader
}

func NewPipeline(e Extractor, l Loader) *Pipeline {
	return &Pipeline{extractor: e, loader: l}
}

func (p *Pipeline) Process(ctx context.Context, target string, data []byte) error {
	result, err := p.extractor.Extract(ctx, target, data)
	if err != nil {
		return err
	}
	if result == nil || len(result.Entities) == 0 {
		return nil
	}
	return p.loader.Save(ctx, result)
}
