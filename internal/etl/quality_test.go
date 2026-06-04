package etl

import "testing"

func TestNormalizeURL(t *testing.T) {
	got, meta, ok := normalizeURL("HTTP://Example.COM:80//admin/../login?b=2&a=1#frag")
	if !ok {
		t.Fatal("expected URL to normalize")
	}
	want := "http://example.com/login?a=1&b=2"
	if got != want {
		t.Fatalf("normalizeURL = %q, want %q", got, want)
	}
	if meta.Host != "example.com" || meta.Path != "/login" || meta.Query != "a=1&b=2" {
		t.Fatalf("unexpected meta: %#v", meta)
	}
}

func TestBuildHTTPQuality(t *testing.T) {
	_, quality := buildHTTPQuality(HTTPQualityInput{
		URL:        "https://example.com/actuator/env",
		StatusCode: 200,
	})
	if quality.Layer != "critical" || quality.Noise {
		t.Fatalf("expected critical non-noise actuator URL, got %#v", quality)
	}

	_, quality = buildHTTPQuality(HTTPQualityInput{
		URL:        "https://example.com/random",
		StatusCode: 404,
	})
	if quality.Layer != "noise" || !quality.Noise {
		t.Fatalf("expected 404 noise, got %#v", quality)
	}

	_, quality = buildHTTPQuality(HTTPQualityInput{
		URL:           "https://example.com/random",
		StatusCode:    200,
		ContentLength: 32,
	})
	if quality.Layer != "noise" || !quality.Noise {
		t.Fatalf("expected tiny 200 soft404 noise, got %#v", quality)
	}
}
