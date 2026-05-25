---
id: commands
title: Command Reference
---

# Command Reference

## Usage

```text
ammit [global flags] <command> [target]
```

## Commands

| Command | Purpose |
|---|---|
| `ammit ls` | List target containers |
| `ammit config <target>` | Show image, env, mounts, capabilities, limits, restart policy |
| `ammit net <target>` | Show network mode, attached networks, bindings, live counters |
| `ammit stats <target>` | Show CPU, memory, block I/O, and network usage |
| `ammit recommend <target>` | Show tuning recommendations |
| `ammit scan <target>` | Run config security checks and optional CVE scan |
| `ammit all <target>` | Run config, net, stats, recommend, scan in one pass |

## Global flags

- `-H, --host <string>` Docker host endpoint.
- `--no-color` Disable ANSI coloring.
- `--json` Emit machine-readable JSON output.
- `--cve` Enable Trivy CVE scan in `scan` and `all`.
- `--watch` Enable streaming mode for `stats`.
- `--watch-interval <duration>` Refresh interval for `--watch` (default `2s`).
- `-h, --help` Show help.
- `-v, --version` Show version.
