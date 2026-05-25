// Package scan performs security analysis of a container. It always runs a set
// of dependency-free configuration checks (privilege, capabilities, mounts,
// exposure) and optionally shells out to Trivy for full CVE scanning when the
// binary is present.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/SvenNellerz/ammit/internal/docker"
)

// Finding is a single security result.
type Finding struct {
	Severity string // CRITICAL, HIGH, MEDIUM, LOW, PASS
	Check    string
	Detail   string
}

// dangerousCaps are Linux capabilities that materially widen the blast radius.
var dangerousCaps = map[string]string{
	"SYS_ADMIN":       "near-root; can mount filesystems, manipulate namespaces",
	"NET_ADMIN":       "can reconfigure host networking",
	"SYS_PTRACE":      "can inspect/modify other processes' memory",
	"SYS_MODULE":      "can load kernel modules (full host compromise)",
	"DAC_READ_SEARCH": "can bypass file read permission checks",
	"SYS_RAWIO":       "raw I/O port access",
}

// sensitiveMounts are host paths that, when bind-mounted, are commonly abused.
var sensitiveMounts = map[string]string{
	"/var/run/docker.sock": "grants control of the Docker daemon = root on host",
	"/":                    "host root filesystem mounted into container",
	"/etc":                 "host configuration exposed",
	"/proc":                "host process table exposed",
	"/sys":                 "host kernel interfaces exposed",
	"/var/run":             "host runtime sockets exposed",
}

// Config runs the built-in configuration checks against an inspection.
func Config(ins *docker.Inspection) []Finding {
	var f []Finding
	add := func(sev, check, detail string) { f = append(f, Finding{sev, check, detail}) }

	// Privileged mode.
	if ins.HostConfig.Privileged {
		add("CRITICAL", "Privileged mode",
			"Container runs --privileged: it has nearly all host capabilities and device access. Avoid unless strictly required.")
	} else {
		add("PASS", "Privileged mode", "Not privileged.")
	}

	// Running as root.
	user := strings.TrimSpace(ins.Config.User)
	if user == "" || user == "root" || strings.HasPrefix(user, "0") {
		add("HIGH", "Runs as root",
			"No non-root USER set. A container escape inherits root. Set USER to an unprivileged uid.")
	} else {
		add("PASS", "Runs as root", "Runs as non-root user "+user+".")
	}

	// Dangerous capabilities.
	for _, cap := range ins.HostConfig.CapAdd {
		name := strings.TrimPrefix(strings.ToUpper(cap), "CAP_")
		if reason, bad := dangerousCaps[name]; bad {
			add("HIGH", "Dangerous capability: "+name, "Added capability — "+reason+".")
		}
	}

	// Capability hardening: did they drop ALL?
	droppedAll := false
	for _, d := range ins.HostConfig.CapDrop {
		if strings.EqualFold(d, "ALL") {
			droppedAll = true
		}
	}
	if droppedAll {
		add("PASS", "Capability hardening", "Drops ALL capabilities (good baseline).")
	} else {
		add("LOW", "Capability hardening",
			"Container does not drop ALL capabilities. Consider --cap-drop ALL then add back only what is needed.")
	}

	// Sensitive bind mounts.
	for _, b := range ins.HostConfig.Binds {
		src := b
		if i := strings.Index(b, ":"); i >= 0 {
			src = b[:i]
		}
		if reason, bad := sensitiveMounts[src]; bad {
			add("CRITICAL", "Sensitive host mount: "+src, reason+".")
		}
	}
	for _, mnt := range ins.Mounts {
		if reason, bad := sensitiveMounts[mnt.Source]; bad {
			sev := "HIGH"
			if mnt.RW {
				sev = "CRITICAL"
			}
			rw := "read-only"
			if mnt.RW {
				rw = "READ-WRITE"
			}
			add(sev, "Sensitive host mount: "+mnt.Source, fmt.Sprintf("%s (%s).", reason, rw))
		}
	}

	// Read-only root filesystem.
	if ins.HostConfig.ReadonlyRootfs {
		add("PASS", "Read-only rootfs", "Root filesystem is read-only.")
	} else {
		add("LOW", "Read-only rootfs",
			"Root filesystem is writable. Consider --read-only with explicit tmpfs/volumes for paths that need writes.")
	}

	// no-new-privileges.
	hasNNP := false
	for _, o := range ins.HostConfig.SecurityOpt {
		if strings.Contains(o, "no-new-privileges") {
			hasNNP = true
		}
	}
	if hasNNP {
		add("PASS", "no-new-privileges", "Set; setuid binaries cannot escalate.")
	} else {
		add("LOW", "no-new-privileges",
			"Not set. Add --security-opt no-new-privileges to block privilege escalation via setuid binaries.")
	}

	// Host namespaces.
	if ins.HostConfig.PidMode == "host" {
		add("HIGH", "Host PID namespace", "Shares the host PID namespace; can see and signal host processes.")
	}
	if strings.HasPrefix(ins.HostConfig.NetworkMode, "host") {
		add("MEDIUM", "Host network namespace", "Uses host networking; no network isolation from the host.")
	}
	if ins.HostConfig.IpcMode == "host" {
		add("MEDIUM", "Host IPC namespace", "Shares host IPC; can access host shared memory.")
	}

	// Exposed ports bound to all interfaces.
	for port, bindings := range ins.HostConfig.PortBindings {
		for _, b := range bindings {
			if b.HostIP == "" || b.HostIP == "0.0.0.0" || b.HostIP == "::" {
				add("LOW", "Port exposed on all interfaces",
					fmt.Sprintf("%s published on %s:%s. Bind to 127.0.0.1 if it need not be public.", port, orAll(b.HostIP), b.HostPort))
			}
		}
	}

	return f
}

func orAll(ip string) string {
	if ip == "" {
		return "0.0.0.0"
	}
	return ip
}

// trivyReport is the slice of Trivy's JSON we consume.
type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// TrivyAvailable reports whether the trivy binary is on PATH.
func TrivyAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

// CVEs runs `trivy image` against the container's image and returns findings.
// Returns (nil, nil) with a helpful message handled by the caller if trivy is
// missing. The scan can be slow on first run (DB download), so we give it a
// generous timeout.
func CVEs(ctx context.Context, image string) ([]Finding, error) {
	if !TrivyAvailable() {
		return nil, fmt.Errorf("trivy not found on PATH")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "trivy", "image",
		"--quiet", "--format", "json", "--scanners", "vuln", image)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running trivy: %w", err)
	}

	var rep trivyReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	var f []Finding
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			fix := v.FixedVersion
			if fix == "" {
				fix = "no fix yet"
			}
			f = append(f, Finding{
				Severity: v.Severity,
				Check:    v.VulnerabilityID + " (" + v.PkgName + ")",
				Detail:   fmt.Sprintf("%s %s → %s", v.InstalledVersion, arrow(), fix),
			})
		}
	}
	return f, nil
}

func arrow() string { return "fixed in" }

// Summarise counts findings by severity for a one-line headline.
func Summarise(findings []Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.ToUpper(f.Severity)]++
	}
	return counts
}
