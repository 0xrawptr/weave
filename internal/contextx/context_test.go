package contextx

import (
	"context"
	"testing"
)

func TestCampaignIDContext(t *testing.T) {
	ctx := WithCampaignID(context.Background(), "camp-1")
	if got := CampaignIDFromContext(ctx); got != "camp-1" {
		t.Fatalf("campaign id = %q", got)
	}
	if got := CampaignIDFromContext(WithCampaignID(context.Background(), "")); got != "" {
		t.Fatalf("empty campaign id should not be set, got %q", got)
	}
}
