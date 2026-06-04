package data

import (
	"net"
	"strings"
)

func TargetType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return "url"
	}
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			return "cidr"
		}
	}
	if net.ParseIP(raw) != nil {
		return "ip"
	}
	if strings.Contains(raw, ".") {
		return "domain"
	}
	return "unknown"
}
