---
id: quickstart
title: Quickstart
---

# Quickstart

## Build native binary

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ammit ./cmd/ammit
./ammit ls
```

## Build container image

```sh
docker build -t ammit:latest .
```

## Run as sidecar

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ammit:latest all my-target-container
```

## Namespace-sharing run

```sh
docker run --rm \
  --network=container:my-target \
  --pid=container:my-target \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ammit:latest net my-target
```
