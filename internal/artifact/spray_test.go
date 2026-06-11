package artifact

import (
	"testing"

	"github.com/chainreactors/fingers/common"
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

func TestSprayResultItemPreservesFrameworksAndExtracts(t *testing.T) {
	item := sprayResultItem(&sdktypes.SprayResult{
		UrlString: "https://example.com/console",
		Status:    200,
		IsValid:   true,
		Frameworks: sdktypes.Frameworks{
			"tongweb": &sdktypes.Framework{
				Name:    "TongWeb",
				Tags:    []string{"java", "appserver"},
				IsFocus: true,
				Attributes: &common.Attributes{
					Version: "7.0",
				},
				MatchDetail: &sdktypes.MatchDetail{
					RuleIndex:    2,
					MatcherType:  "body",
					MatcherIndex: 1,
					MatcherValue: "TongWeb",
					SendData:     "/console",
				},
			},
		},
		Extracteds: sdktypes.Extracteds{
			{Name: "url", Severity: "info", ExtractResult: []string{"https://example.com/api"}},
		},
	})

	if len(item.Frameworks) != 1 {
		t.Fatalf("expected framework metadata, got %#v", item.Frameworks)
	}
	fw := item.Frameworks[0]
	if fw.Name != "TongWeb" || fw.Version != "7.0" || fw.MatchDetail["matcher_type"] != "body" {
		t.Fatalf("framework metadata not preserved: %#v", fw)
	}
	if len(item.Extracts) != 1 || item.Extracts[0].Values[0] != "https://example.com/api" {
		t.Fatalf("extract metadata not preserved: %#v", item.Extracts)
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

func TestFullSprayWordlistUsesDefaultDictionary(t *testing.T) {
	words := FullSprayWordlist()
	if len(words) == 0 {
		t.Fatal("expected default spray wordlist")
	}
	if len(words) != len(defaultSprayWordlist()) {
		t.Fatalf("full wordlist should map to default dictionary, got %d", len(words))
	}
}
