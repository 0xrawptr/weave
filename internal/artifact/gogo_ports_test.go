package artifact

import (
	"testing"

	gogopkg "github.com/chainreactors/gogo/v2/pkg"
)

func TestValidateGogoPorts(t *testing.T) {
	if err := gogopkg.LoadPortConfig(""); err != nil {
		t.Fatalf("load gogo port config: %v", err)
	}
	if err := validateGogoPorts(""); err == nil {
		t.Fatalf("empty ports should fail validation")
	}
	if err := validateGogoPorts("top1000"); err == nil {
		t.Fatalf("unknown top1000 preset should fail validation")
	}
	if err := validateGogoPorts("80,443,8080"); err != nil {
		t.Fatalf("explicit ports should validate: %v", err)
	}
	if err := validateGogoPorts("top1,top2,top3,ssh,db,win,common"); err != nil {
		t.Fatalf("common HW port presets should validate: %v", err)
	}
	if err := validateGogoPorts("top1,top2,top3,ssh,db,windows"); err != nil {
		t.Fatalf("windows port preset should validate: %v", err)
	}
	if err := validateGogoPorts("definitely-not-a-port-preset"); err == nil {
		t.Fatalf("unknown port preset should fail validation")
	}
	if err := validateGogoPorts("top1+top2"); err == nil {
		t.Fatalf("plus-separated presets should fail validation")
	}
}
