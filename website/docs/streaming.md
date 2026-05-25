---
id: streaming
title: Streaming Mode
---

# Streaming Mode

Use `--watch` with `stats` to continuously refresh live metrics.

```sh
ammit --watch stats my-target
ammit --watch --watch-interval 1s stats my-target
```

## Rules

- `--watch` works only with `stats`.
- `--watch` cannot be combined with `--json`.
- `--watch-interval` must be greater than zero.
