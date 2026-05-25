---
id: intro
title: ammit Overview
slug: /
---

# ammit

> Weigh every container. Devour the unworthy.

ammit is a focused Docker diagnostics and security CLI for operators who need fast signal without noisy dashboards.

<div className="home-panels">
	<a className="home-panel" href="./quickstart">
		<h3>Quickstart</h3>
		<p>Build, run, and inspect your first target in minutes.</p>
	</a>
	<a className="home-panel" href="./commands">
		<h3>Command Reference</h3>
		<p>Full command list with flags and execution patterns.</p>
	</a>
	<a className="home-panel" href="./security">
		<h3>Security Model</h3>
		<p>Understand verdicts, checks, and hardening priorities.</p>
	</a>
	<a className="home-panel" href="./json-automation">
		<h3>Automation</h3>
		<p>Consume typed JSON output in CI, bots, and pipelines.</p>
	</a>
</div>

## Why teams use ammit

- Single static binary with zero third-party Go dependencies.
- Runtime-first diagnostics: config, networking, resources, and risk.
- Security verdicts with optional CVE scan path.
- Streaming and JSON output modes for operators and automation.

## Core flow

```sh
ammit ls
ammit all my-target-container
```

## Key commands

| Command | Outcome |
| --- | --- |
| `ammit config <target>` | Runtime configuration, privileges, limits, mounts |
| `ammit net <target>` | Network mode, interfaces, ports, counters |
| `ammit stats <target>` | CPU, memory, block I/O, network usage |
| `ammit recommend <target>` | Actionable tuning and hardening suggestions |
| `ammit scan <target>` | Security checks with optional image CVE scan |

Continue to [Quickstart](quickstart) to get running.
