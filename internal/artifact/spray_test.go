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

func TestSliceWordlist(t *testing.T) {
	words := []string{"a", "b", "c", "d"}
	got := sliceWordlist(words, 1, 2)
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("sliceWordlist = %#v", got)
	}
	got[0] = "changed"
	if words[1] == "changed" {
		t.Fatalf("sliceWordlist should return a copy")
	}
	if got := sliceWordlist(words, 10, 2); len(got) != 0 {
		t.Fatalf("out of range slice = %#v", got)
	}
}
