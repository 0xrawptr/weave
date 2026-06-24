package runtime

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/etl"
	"github.com/chainreactors/sdk/pkg/association"
)

type RawEventProcessor struct {
	app *app.App
}

type RawEventProcessRequest struct {
	Artifact      string
	Target        string
	WorkflowID    string
	CampaignID    string
	PersistData   []byte
	ETLData       []byte
	PreEnrichment *association.QueryResult
	AfterETL      func(context.Context) error
}

func NewRawEventProcessor(runtimeApp *app.App) *RawEventProcessor {
	return &RawEventProcessor{app: runtimeApp}
}

func (p *RawEventProcessor) Process(ctx context.Context, req RawEventProcessRequest) {
	if p == nil || p.app == nil || p.app.Repo == nil {
		return
	}
	if len(req.PersistData) > 0 {
		if err := p.app.Repo.SaveRawEvent(ctx, &data.RawEvent{
			ID:         rawEventID(req.Artifact, req.WorkflowID),
			CampaignID: req.CampaignID,
			Artifact:   req.Artifact,
			TargetID:   req.Target,
			TargetType: targetType(req.Target),
			WorkflowID: req.WorkflowID,
			Data:       req.PersistData,
		}); err != nil {
			log.Printf("WARNING: raw event save failed for %s: %v", req.Artifact, err)
		}
	}
	if len(req.ETLData) == 0 {
		return
	}
	etlCtx := ctx
	if req.PreEnrichment != nil {
		etlCtx = etl.WithPreEnrichment(etlCtx, req.PreEnrichment)
	}
	if err := p.app.ProcessArtifactETL(etlCtx, req.Artifact, req.Target, req.CampaignID, req.ETLData); err != nil {
		log.Printf("WARNING: ETL failed for %s: %v", req.Artifact, err)
		return
	}
	if req.AfterETL != nil {
		if err := req.AfterETL(ctx); err != nil {
			log.Printf("WARNING: post-ETL hook failed for %s: %v", req.Artifact, err)
		}
	}
}

func rawEventID(artifactName, workflowID string) string {
	if workflowID == "" {
		workflowID = artifactName
	}
	return fmt.Sprintf("%s-%d", workflowID, time.Now().UnixNano())
}
