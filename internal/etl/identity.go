package etl

import (
	"net"
	"net/url"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

type targetRef struct {
	ID    string
	Type  string
	Value string
}

func targetForValue(value string) targetRef {
	value = strings.TrimSpace(value)
	return targetRef{ID: data.TargetID(value), Type: inferTargetType(value), Value: value}
}

func targetForHost(host string) targetRef {
	host = strings.TrimSpace(host)
	return targetRef{ID: data.TargetID(host), Type: inferHostTargetType(host), Value: host}
}

func targetForURL(rawURL string) targetRef {
	canonical, _, ok := normalizeURL(rawURL)
	if ok {
		rawURL = canonical
	}
	return targetRef{ID: data.TargetID(rawURL), Type: "url", Value: rawURL}
}

func applyTarget(entity *Entity, target targetRef) {
	entity.TargetID = target.ID
	entity.TargetType = target.Type
	entity.TargetValue = target.Value
}

func assetID(entityType, value string) string {
	return data.GenerateID(entityType, strings.TrimSpace(value))
}

func evidenceID(entityType string, target targetRef, value string, extra ...string) string {
	parts := []string{entityType, target.ID, strings.TrimSpace(value)}
	parts = append(parts, extra...)
	return data.GenerateID(parts...)
}

func inferTargetType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return "cidr"
	}
	if parsed := net.ParseIP(value); parsed != nil {
		return "ip"
	}
	if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.Host != "" {
		return "url"
	}
	return inferHostTargetType(value)
}

func inferHostTargetType(value string) string {
	host := strings.TrimSpace(value)
	if host == "" {
		return "unknown"
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return "ip"
	}
	return "domain"
}
