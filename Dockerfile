# syntax=docker/dockerfile:1

# ---- build stage ----
# Pin a small builder. CGO is disabled so the binary is fully static and can
# run in a scratch image on any distribution / architecture.
FROM golang:1.26.3-alpine AS build
WORKDIR /src

# No third-party deps, so this is just the module file + source.
COPY go.mod ./
COPY . .

# Build a stripped, static binary. -trimpath keeps paths reproducible.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ammit ./cmd/ammit

# ---- runtime stage ----
# scratch = nothing but our binary. Final image is just a few MB.
FROM scratch
COPY --from=build /out/ammit /ammit

# The binary talks to the Docker socket, which you bind-mount at runtime.
ENTRYPOINT ["/ammit"]
CMD ["--help"]
