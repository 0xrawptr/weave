package artifact

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

func TestFallbackExecutionStatCountsCommonOutputs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want int64
	}{
		{name: "total", raw: []byte(`{"total":3}`), want: 3},
		{name: "count", raw: []byte(`{"count":2}`), want: 2},
		{name: "results", raw: []byte(`{"results":[{},{}]}`), want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := fallbackExecutionStat("fingers", "example.com", &ActivityResult{
				Success:  true,
				Data:     tt.raw,
				Duration: 123,
			})
			if stat.Results != tt.want {
				t.Fatalf("results = %d, want %d", stat.Results, tt.want)
			}
			if stat.Engine != "fingers" || stat.Task != "example.com" || stat.Targets != 1 || stat.DurationMs != 123 {
				t.Fatalf("unexpected stat metadata: %#v", stat)
			}
		})
	}
}

func TestFallbackExecutionStatMarksErrors(t *testing.T) {
	stat := fallbackExecutionStat("nuclei", "example.com", &ActivityResult{Success: false, Error: "boom"})
	if stat.Errors != 1 {
		t.Fatalf("errors = %d, want 1", stat.Errors)
	}
}
