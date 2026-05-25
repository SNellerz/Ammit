package inspect

import (
	"testing"

	"github.com/SvenNellerz/ammit/internal/docker"
)

func TestComputeMemoryWorkingSet(t *testing.T) {
	s := &docker.StatsSample{}
	s.MemoryStats.Usage = 200 << 20 // 200 MiB
	s.MemoryStats.Limit = 512 << 20 // 512 MiB
	s.MemoryStats.Stats.Cache = 50 << 20

	m := Compute(s)
	if got := m.MemUsage; got != 150<<20 {
		t.Fatalf("working set = %d, want %d", got, 150<<20)
	}
	if m.MemPercent < 29 || m.MemPercent > 30 {
		t.Fatalf("mem percent = %.2f, want ~29.3", m.MemPercent)
	}
}

func TestComputeCPUPercent(t *testing.T) {
	s := &docker.StatsSample{}
	s.CPUStats.CPUUsage.TotalUsage = 2_000_000
	s.PreCPUStats.CPUUsage.TotalUsage = 1_000_000
	s.CPUStats.SystemCPUUsage = 10_000_000
	s.PreCPUStats.SystemCPUUsage = 8_000_000
	s.CPUStats.OnlineCPUs = 4

	m := Compute(s)
	// delta cpu = 1e6, delta sys = 2e6, ratio 0.5 * 4 cpus * 100 = 200%
	if m.CPUPercent < 199 || m.CPUPercent > 201 {
		t.Fatalf("cpu percent = %.2f, want ~200", m.CPUPercent)
	}
}

func TestRecommendNoMemoryLimit(t *testing.T) {
	ins := &docker.Inspection{}
	recs := Recommend(ins, Metrics{})
	found := false
	for _, r := range recs {
		if r.Title == "No memory limit set" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a 'No memory limit set' recommendation")
	}
}

func TestRecommendHealthyIsInfo(t *testing.T) {
	ins := &docker.Inspection{}
	ins.HostConfig.Memory = 256 << 20
	ins.HostConfig.NanoCpus = 1e9
	ins.HostConfig.RestartPolicy.Name = "unless-stopped"
	ins.Config.Healthcheck = &struct {
		Test []string `json:"Test"`
	}{Test: []string{"CMD", "true"}}

	recs := Recommend(ins, Metrics{MemLimit: 256 << 20, MemUsage: 100 << 20, MemPercent: 40})
	if len(recs) != 1 || recs[0].Severity != "INFO" {
		t.Fatalf("expected single INFO rec, got %+v", recs)
	}
}
