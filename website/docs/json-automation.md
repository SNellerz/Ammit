---
id: json-automation
title: JSON and Automation
---

# JSON and Automation

Use `--json` for machine consumption.

```sh
ammit --json ls
ammit --json config my-api
ammit --json scan --cve my-api
```

## Envelope

```json
{
  "tool": "ammit",
  "version": "0.1.0",
  "ok": true,
  "command": "scan",
  "target": "my-api",
  "output": "...human-readable output...",
  "data": {}
}
```

## Error format

```json
{
  "ok": false,
  "error": {
    "code": "AMMIT_E_TARGET_NOT_FOUND",
    "message": "no container matching \"api\""
  }
}
```

## Stable error codes

- `AMMIT_E_INVALID_FLAGS`
- `AMMIT_E_UNKNOWN_COMMAND`
- `AMMIT_E_TARGET_REQUIRED`
- `AMMIT_E_TARGET_NOT_FOUND`
- `AMMIT_E_TARGET_AMBIGUOUS`
- `AMMIT_E_DOCKER_HOST`
- `AMMIT_E_DOCKER_CONNECT`
- `AMMIT_E_DOCKER_API`
