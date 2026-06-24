package contextx

import "context"

type campaignIDKey struct{}

func WithCampaignID(ctx context.Context, campaignID string) context.Context {
	if campaignID == "" {
		return ctx
	}
	return context.WithValue(ctx, campaignIDKey{}, campaignID)
}

func CampaignIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(campaignIDKey{}).(string)
	return value
}
