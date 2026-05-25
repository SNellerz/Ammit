package scan

import (
	"strings"
	"testing"

	"github.com/SvenNellerz/ammit/internal/docker"
)

func TestConfigFindsPrivilegedAndRoot(t *testing.T) {
	ins := &docker.Inspection{}
	ins.HostConfig.Privileged = true
	ins.Config.User = ""

	f := Config(ins)
	if !hasCheck(f, "CRITICAL", "Privileged mode") {
		t.Fatalf("expected privileged-mode critical finding, got %+v", f)
	}
	if !hasCheck(f, "HIGH", "Runs as root") {
		t.Fatalf("expected runs-as-root high finding, got %+v", f)
	}
}

func TestConfigRecognizesHardening(t *testing.T) {
	ins := &docker.Inspection{}
	ins.Config.User = "10001"
	ins.HostConfig.ReadonlyRootfs = true
	ins.HostConfig.CapDrop = []string{"ALL"}
	ins.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}

	f := Config(ins)
	if !hasCheck(f, "PASS", "Runs as root") {
		t.Fatalf("expected non-root pass finding, got %+v", f)
	}
	if !hasCheck(f, "PASS", "Read-only rootfs") {
		t.Fatalf("expected read-only-rootfs pass finding, got %+v", f)
	}
	if !hasCheck(f, "PASS", "Capability hardening") {
		t.Fatalf("expected cap-drop pass finding, got %+v", f)
	}
	if !hasCheck(f, "PASS", "no-new-privileges") {
		t.Fatalf("expected nnp pass finding, got %+v", f)
	}
}

func hasCheck(findings []Finding, sev, check string) bool {
	for _, finding := range findings {
		if strings.EqualFold(finding.Severity, sev) && finding.Check == check {
			return true
		}
	}
	return false
}
