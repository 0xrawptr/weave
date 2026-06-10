package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInputJSONResponseRedactsLargeWordlist(t *testing.T) {
	raw := []byte(`{"input":{"base_urls":["http://127.0.0.1/"],"wordlist":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}}`)

	out := inputJSONResponse(raw, false)
	if strings.Contains(string(out), `"u"`) {
		t.Fatalf("expected large wordlist to be redacted: %s", out)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("redacted input is not json: %v", err)
	}
	nested := decoded["input"].(map[string]interface{})
	wordlist := nested["wordlist"].(map[string]interface{})
	if wordlist["redacted"] != true || int(wordlist["count"].(float64)) != 21 {
		t.Fatalf("unexpected wordlist summary: %#v", wordlist)
	}
}

func TestInputJSONResponseKeepsRawInputWhenRequested(t *testing.T) {
	raw := []byte(`{"wordlist":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`)
	out := inputJSONResponse(raw, true)
	if string(out) != string(raw) {
		t.Fatalf("raw input changed: %s", out)
	}
}
