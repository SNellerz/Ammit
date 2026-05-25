---
id: security
title: Security Model
---

# Security Model

## Built-in configuration checks

- Privileged mode and host namespace usage.
- Root-user execution.
- Dangerous capability additions.
- Sensitive host mounts, including Docker socket.
- Read-only rootfs and no-new-privileges posture.
- Ports exposed on all interfaces.

## Optional CVE scanning

- Enable via `--cve` on `scan` or `all`.
- Uses Trivy when available on PATH.
- Continues gracefully if Trivy is missing.

## Brand verdict language

- `DEVOURED` maps to critical findings.
- `WORTHY` maps to pass findings.
