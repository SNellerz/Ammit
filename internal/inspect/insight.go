// Package inspect turns raw Docker data into computed insights and
// human-actionable recommendations.
package inspect

import (
	"fmt"

	"github.com/SvenNellerz/ammit/internal/docker"
)

// Metrics holds derived numbers from a stats sample.
type Metrics struct {
	CPUPercent    float64
	OnlineCPUs    uint32
	MemUsage      uint64 // working set (usage minus page cache where possible)
	MemLimit      uint64
	MemPercent    float64
	BlkReadBytes  uint64
	BlkWriteBytes uint64
	NetRxBytes    uint64
	NetTxBytes    uint64
	NetRxErrors   uint64
	NetTxErrors   uint64
	NetRxDropped  uint64
	NetTxDropped  uint64
}

// Compute derives metrics from a single stats sample. CPU percent is computed
// from the delta between cpu and precpu fields that the one-shot sample
// includes.
func Compute(s *docker.StatsSample) Metrics {
	var m Metrics

	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemCPUUsage) - float64(s.PreCPUStats.SystemCPUUsage)
	cpus := s.CPUStats.OnlineCPUs
	if cpus == 0 {
		cpus = uint32(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if cpus == 0 {
		cpus = 1
	}
	if sysDelta > 0 && cpuDelta > 0 {
		m.CPUPercent = (cpuDelta / sysDelta) * float64(cpus) * 100.0
	}
	m.OnlineCPUs = cpus

	// Working-set memory: prefer usage minus cache/inactive_file so we report
	// genuinely resident memory rather than reclaimable page cache.
	usage := s.MemoryStats.Usage
	cache := s.MemoryStats.Stats.Cache
	if cache == 0 {
		cache = s.MemoryStats.Stats.InactiveFile // cgroup v2
	}
	if cache <= usage {
		m.MemUsage = usage - cache
	} else {
		m.MemUsage = usage
	}
	m.MemLimit = s.MemoryStats.Limit
	if m.MemLimit > 0 {
		m.MemPercent = float64(m.MemUsage) / float64(m.MemLimit) * 100.0
	}

	for _, e := range s.BlkioStats.IoServiceBytesRecursive {
		switch e.Op {
		case "Read", "read":
			m.BlkReadBytes += e.Value
		case "Write", "write":
			m.BlkWriteBytes += e.Value
		}
	}

	for _, n := range s.Networks {
		m.NetRxBytes += n.RxBytes
		m.NetTxBytes += n.TxBytes
		m.NetRxErrors += n.RxErrors
		m.NetTxErrors += n.TxErrors
		m.NetRxDropped += n.RxDropped
		m.NetTxDropped += n.TxDropped
	}
	return m
}

// Recommendation is a single piece of tuning advice.
type Recommendation struct {
	Severity string // INFO, LOW, MEDIUM, HIGH
	Title    string
	Detail   string
}

// Recommend produces tuning advice by combining static config with live
// metrics. This is intentionally heuristic and explains its reasoning so the
// operator can judge each suggestion.
func Recommend(ins *docker.Inspection, m Metrics) []Recommendation {
	var recs []Recommendation
	add := func(sev, title, detail string) {
		recs = append(recs, Recommendation{sev, title, detail})
	}

	// Memory limit hygiene.
	if ins.HostConfig.Memory == 0 {
		add("MEDIUM", "No memory limit set",
			"Container can consume all host memory. Set --memory to bound it and prevent noisy-neighbour OOM events on the host.")
	} else if m.MemLimit > 0 && m.MemPercent > 85 {
		add("HIGH", "Memory near limit",
			fmt.Sprintf("Working set is %.0f%% of the %s limit. Raise the limit or investigate a leak before the kernel OOM-kills the process.", m.MemPercent, bytesShort(m.MemLimit)))
	} else if m.MemLimit > 0 && m.MemPercent < 10 && m.MemLimit > 256<<20 {
		add("LOW", "Memory limit may be oversized",
			fmt.Sprintf("Only %.0f%% of the %s limit is in use. Right-sizing improves bin-packing density on the host.", m.MemPercent, bytesShort(m.MemLimit)))
	}

	// CPU limit hygiene.
	if ins.HostConfig.NanoCpus == 0 {
		add("LOW", "No CPU limit set",
			"Without --cpus the container can saturate all cores. Consider a limit for predictable scheduling under contention.")
	} else if m.CPUPercent > 90 {
		add("MEDIUM", "CPU pegged at limit",
			fmt.Sprintf("Live CPU is %.0f%%. The workload may be throttled; raise --cpus or scale out.", m.CPUPercent))
	}

	// OOM history.
	if ins.State.OOMKilled {
		add("HIGH", "Previously OOM-killed",
			"The kernel has killed this container for exceeding memory. Increase the limit or fix the leak; recurring OOM kills cause silent restarts.")
	}

	// Restart policy.
	if ins.HostConfig.RestartPolicy.Name == "" || ins.HostConfig.RestartPolicy.Name == "no" {
		add("LOW", "No restart policy",
			"Set --restart unless-stopped (or on-failure) so the container recovers from crashes and daemon restarts.")
	}

	// Health check.
	if ins.Config.Healthcheck == nil || len(ins.Config.Healthcheck.Test) == 0 {
		add("LOW", "No health check defined",
			"Add a HEALTHCHECK so orchestrators and `docker ps` can tell whether the app is actually serving, not just running.")
	} else if ins.State.Health != nil && ins.State.Health.Status == "unhealthy" {
		add("HIGH", "Health check failing",
			fmt.Sprintf("Reported unhealthy with a failing streak of %d. Inspect the app logs.", ins.State.Health.FailingStreak))
	}

	// Network error rates.
	if m.NetRxErrors+m.NetTxErrors > 0 {
		add("MEDIUM", "Network interface errors",
			fmt.Sprintf("rx_errors=%d tx_errors=%d. Investigate MTU mismatches or a saturated link.", m.NetRxErrors, m.NetTxErrors))
	}
	if m.NetRxDropped+m.NetTxDropped > 0 {
		add("LOW", "Dropped packets observed",
			fmt.Sprintf("rx_dropped=%d tx_dropped=%d. Often a sign of buffer pressure or an overwhelmed receiver.", m.NetRxDropped, m.NetTxDropped))
	}

	if len(recs) == 0 {
		add("INFO", "No tuning issues detected", "Configuration and live metrics look healthy.")
	}
	return recs
}

func bytesShort(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
