package data

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type ScopeSet struct {
	empty    bool
	hosts    map[string]bool
	domains  []string
	prefixes []netip.Prefix
}

func NewScopeSet(targets []string) ScopeSet {
	out := ScopeSet{hosts: map[string]bool{}}
	for _, target := range targets {
		target = NormalizeHostLike(target)
		if target == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(target); err == nil {
			out.prefixes = append(out.prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(target); err == nil {
			out.prefixes = append(out.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		host := strings.ToLower(target)
		out.hosts[host] = true
		if net.ParseIP(host) == nil {
			out.domains = append(out.domains, host)
		}
	}
	out.empty = len(out.hosts) == 0 && len(out.prefixes) == 0
	return out
}

func (s ScopeSet) Empty() bool {
	return s.empty
}

func (s ScopeSet) Contains(raw string) bool {
	if s.empty {
		return true
	}
	host := NormalizeHostLike(raw)
	if host == "" {
		return true
	}
	if s.hosts[strings.ToLower(host)] {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		for _, prefix := range s.prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	host = strings.ToLower(host)
	for _, domain := range s.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func (s ScopeSet) AllowsAll(values []string) bool {
	if s.empty {
		return true
	}
	for _, value := range values {
		host := NormalizeHostLike(value)
		if host == "" {
			continue
		}
		if IsLoopbackHost(host) && !s.Contains(host) {
			return false
		}
		if !s.Contains(host) {
			return false
		}
	}
	return true
}

func NewScopeMatcher(scanTarget string) func(string) bool {
	scope := NewScopeSet([]string{scanTarget})
	return func(value string) bool {
		return scope.Contains(value)
	}
}

func NormalizeHostLike(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.Trim(u.Hostname(), "[]"))
	}
	if strings.Contains(raw, "/") {
		if _, err := netip.ParsePrefix(raw); err == nil {
			return raw
		}
		return ""
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.Split(raw, ":")
		if len(parts) == 2 {
			host = parts[0]
		}
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func IsLoopbackHost(host string) bool {
	host = strings.ToLower(NormalizeHostLike(host))
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func IsHTTPURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func SeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	default:
		return 0
	}
}
