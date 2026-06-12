package etl

import (
	"crypto/sha1"
	"encoding/hex"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

type HTTPQualityInput struct {
	URL           string
	StatusCode    int
	Title         string
	ContentType   string
	ContentLength int64
	BodyHash      string
	BodySimhash   string
	FaviconHash   string
	Location      string
}

func normalizeURL(rawURL string) (string, HTTPMeta, bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", HTTPMeta{}, false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rawURL, HTTPMeta{URL: rawURL}, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && !isDefaultPort(u.Scheme, port) {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
		port = ""
	}
	u.Fragment = ""
	u.Path = normalizePath(u.Path)
	u.RawQuery = normalizeQuery(u.Query())
	value := u.String()
	return value, HTTPMeta{
		URL:    value,
		Scheme: u.Scheme,
		Host:   host,
		Port:   port,
		Path:   u.Path,
		Query:  u.RawQuery,
	}, true
}

func buildHTTPQuality(input HTTPQualityInput) (string, Quality) {
	canonical, meta, _ := normalizeURL(input.URL)
	meta.StatusCode = input.StatusCode
	meta.Title = strings.TrimSpace(input.Title)
	meta.ContentType = strings.TrimSpace(input.ContentType)
	meta.ContentLength = input.ContentLength
	meta.BodyHash = strings.TrimSpace(input.BodyHash)
	meta.BodySimhash = strings.TrimSpace(input.BodySimhash)
	meta.FaviconHash = strings.TrimSpace(input.FaviconHash)
	meta.Location = strings.TrimSpace(input.Location)
	meta.Signature = httpSignature(meta)

	quality := Quality{
		CanonicalValue: canonical,
		Layer:          "normal",
		HTTP:           meta,
	}
	applyHTTPQuality(&quality)
	return canonical, quality
}

func applyHTTPQuality(q *Quality) {
	status := q.HTTP.StatusCode
	switch {
	case status == 0:
		q.Layer = "normal"
	case status >= 200 && status < 400:
		q.Layer = "normal"
	case status == 401 || status == 403:
		q.Layer = "interesting"
		q.Reasons = append(q.Reasons, "auth_required")
	case status == 404 || status == 410:
		q.Layer = "noise"
		q.Noise = true
		q.Reasons = append(q.Reasons, "not_found_status")
	case status >= 400 && status < 500:
		q.Layer = "noise"
		q.Noise = true
		q.Reasons = append(q.Reasons, "client_error_status")
	case status >= 500:
		q.Layer = "interesting"
		q.Reasons = append(q.Reasons, "server_error_status")
	}

	pathValue := strings.ToLower(q.HTTP.Path)
	switch {
	case highRiskPath(pathValue):
		q.Layer = "critical"
		q.Noise = false
		q.Reasons = append(q.Reasons, "high_risk_path")
	case interestingPath(pathValue):
		if q.Layer == "normal" {
			q.Layer = "interesting"
		}
		q.Noise = false
		q.Reasons = append(q.Reasons, "interesting_path")
	}

	if looksLikeSoft404(q.HTTP) && q.Layer != "critical" {
		q.Layer = "noise"
		q.Noise = true
		q.Reasons = append(q.Reasons, "soft404_signature")
	}
}

func httpConfidence(statusCode int, quality Quality) float64 {
	if quality.Noise {
		return 0.2
	}
	switch {
	case statusCode >= 200 && statusCode < 400:
		return 0.9
	case statusCode == 401 || statusCode == 403:
		return 0.8
	case statusCode >= 500:
		return 0.65
	case statusCode >= 400:
		return 0.35
	default:
		return 0.7
	}
}

func qualityStatus(quality Quality, fallback string) string {
	if quality.Noise {
		return "noise"
	}
	switch quality.Layer {
	case "critical", "interesting":
		return "candidate"
	case "normal":
		return "queued"
	}
	if fallback == "" {
		return "observed"
	}
	return fallback
}

func normalizePath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func normalizeQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := url.Values{}
	for _, key := range keys {
		items := append([]string{}, values[key]...)
		sort.Strings(items)
		out[key] = items
	}
	return out.Encode()
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

func httpSignature(meta HTTPMeta) string {
	parts := []string{
		meta.Host,
		strconv.Itoa(meta.StatusCode),
		strings.ToLower(meta.ContentType),
		strings.ToLower(meta.Title),
		meta.BodyHash,
		meta.BodySimhash,
		meta.FaviconHash,
		strconv.FormatInt(meta.ContentLength, 10),
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:8])
}

func looksLikeSoft404(meta HTTPMeta) bool {
	text := strings.ToLower(strings.Join([]string{meta.Title, meta.Location}, " "))
	if strings.Contains(text, "404") || strings.Contains(text, "not found") ||
		strings.Contains(text, "页面不存在") || strings.Contains(text, "不存在") {
		return true
	}
	if meta.StatusCode == 200 && meta.ContentLength > 0 && meta.ContentLength < 80 &&
		(meta.Path != "/" && meta.Path != "") {
		return true
	}
	return false
}

func highRiskPath(p string) bool {
	return strings.Contains(p, "/actuator/env") ||
		strings.Contains(p, "/actuator/configprops") ||
		strings.Contains(p, "/actuator/heapdump") ||
		strings.Contains(p, "/actuator/jolokia") ||
		strings.Contains(p, "/actuator/logfile")
}

func interestingPath(p string) bool {
	for _, token := range []string{
		"/actuator", "/v3/api-docs", "/swagger", "/api-docs", "/openapi",
		"/admin", "/login", "/console", "/manager", "/debug", "/metrics", "/config", "/env",
	} {
		if strings.Contains(p, token) {
			return true
		}
	}
	return false
}
