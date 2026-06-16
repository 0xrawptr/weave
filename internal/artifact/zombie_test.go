package artifact

import (
	"testing"

	sdkzombie "github.com/chainreactors/sdk/zombie"
)

func TestParseZombieTargetUsesSchemeService(t *testing.T) {
	target := parseZombieTarget("redis://127.0.0.1:6379")
	if target.IP != "127.0.0.1" || target.Port != "6379" || target.Service != "redis" || target.Scheme != "redis" {
		t.Fatalf("unexpected target: %#v", target)
	}
}

func TestParseZombieTargetInfersCommonServiceFromPort(t *testing.T) {
	target := parseZombieTarget("127.0.0.1:22")
	if target.IP != "127.0.0.1" || target.Port != "22" || target.Service != "ssh" {
		t.Fatalf("unexpected target: %#v", target)
	}
}

func TestApplySniperAuths(t *testing.T) {
	targets := []sdkzombie.Target{
		{IP: "127.0.0.1", Port: "22", Service: "ssh"},
		{IP: "127.0.0.2", Port: "6379", Service: "redis"},
	}
	applySniperAuths(targets, []ZombieAuth{{Username: "root", Password: "toor"}})
	for _, target := range targets {
		if target.Username != "root" || target.Password != "toor" {
			t.Fatalf("expected shared sniper auth, got %#v", targets)
		}
	}
}
