package artifact

import (
	"context"
	"testing"
	"time"

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

func TestSprayResultItemAddsRedirectDedupGroup(t *testing.T) {
	item := sprayResultItem(&sdktypes.SprayResult{
		UrlString:   "https://example.com/admin",
		Status:      302,
		RedirectURL: "/login/auth",
		IsValid:     true,
	})
	if item.DedupGroup != "redirect:example.com:302:/login/auth" {
		t.Fatalf("DedupGroup = %q", item.DedupGroup)
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
					Part:    "a",
					Vendor:  "tongtech",
					Product: "tongweb",
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
	if fw.Name != "TongWeb" || fw.Product != "tongweb" || fw.Version != "7.0" || fw.CPE == "" || fw.MatchDetail["matcher_type"] != "body" {
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

func TestCollectSprayResultsReturnsWhenChannelCloses(t *testing.T) {
	ch := make(chan sdktypes.Result)
	close(ch)

	called := false
	if err := collectSprayResults(context.Background(), ch, func(sdktypes.Result) {
		called = true
	}); err != nil {
		t.Fatalf("collectSprayResults returned error: %v", err)
	}
	if called {
		t.Fatal("handler should not be called for closed channel")
	}
}

func TestCollectSprayResultsStopsOnContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := collectSprayResults(ctx, make(chan sdktypes.Result), func(sdktypes.Result) {})
	if err != context.DeadlineExceeded {
		t.Fatalf("collectSprayResults error = %v, want deadline exceeded", err)
	}
}

func TestSprayWatchdogOutputIdentifiesLocalDeadline(t *testing.T) {
	out := sprayWatchdogOutput("example.com", "spray", context.Background(), context.DeadlineExceeded, 2*time.Minute)
	if out.Success {
		t.Fatal("watchdog output should fail")
	}
	if out.Error != "spray execution watchdog exceeded after 2m0s" {
		t.Fatalf("watchdog error = %q", out.Error)
	}
}

func TestSprayArtifactDefaultTimeout(t *testing.T) {
	spray := NewSprayArtifactFromEngine(nil)
	spray.SetDefaultTimeout(120 * time.Second)
	if spray.defaultTimeout != 120 {
		t.Fatalf("default timeout = %d, want 120", spray.defaultTimeout)
	}
}
