package etl

import "context"

type Extractor interface {
	Extract(ctx context.Context, target string, data []byte) (*ExtractResult, error)
}

type Loader interface {
	Save(ctx context.Context, result *ExtractResult) error
}

// Pipeline runs extract → enrich → load.
type Pipeline struct {
	extractor Extractor
	enricher  Enricher // optional
	loader    Loader
}

func NewPipeline(e Extractor, l Loader) *Pipeline {
	return &Pipeline{extractor: e, loader: l}
}

// WithEnricher attaches an optional enrichment phase between extract and load.
func (p *Pipeline) WithEnricher(e Enricher) *Pipeline {
	p.enricher = e
	return p
}

func (p *Pipeline) Process(ctx context.Context, target string, data []byte) error {
	result, err := p.extractor.Extract(ctx, target, data)
	if err != nil {
		return err
	}
	if result == nil || len(result.Entities) == 0 {
		return nil
	}
	if p.enricher != nil {
		if result, err = p.enricher.Enrich(ctx, result); err != nil {
			return err
		}
	}
	return p.loader.Save(ctx, result)
}
