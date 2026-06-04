package artifact

import (
	"testing"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
)

func TestSprayResultItemPreservesHTTPMetadata(t *testing.T) {
	item := sprayResultItem(&sdktypes.SprayResult{
		UrlString:   "https://example.com/favicon.ico",
		Status:      200,
		Title:       "Example",
		ContentType: "image/x-icon",
		BodyLength:  1234,
		RedirectURL: "https://example.com/login",
		IsValid:     true,
		Reason:      "matched",
		Hashes: &sdktypes.Hashes{
			BodyMd5:     "body-md5",
			BodySimhash: "body-simhash",
			BodyMmh3:    "favicon-mmh3",
		},
	})

	if item.URL != "https://example.com/favicon.ico" {
		t.Fatalf("URL = %q", item.URL)
	}
	if item.Title != "Example" || item.ContentLength != 1234 || item.BodyHash != "body-md5" || item.BodySimhash != "body-simhash" {
		t.Fatalf("metadata not preserved: %#v", item)
	}
	if item.FaviconHash != "favicon-mmh3" {
		t.Fatalf("favicon hash = %q", item.FaviconHash)
	}
}
