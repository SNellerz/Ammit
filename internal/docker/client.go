// Package docker is a minimal, dependency-free client for the Docker Engine
// API. It talks to the daemon over the unix socket (or a tcp host) using only
// the Go standard library, so the resulting binary stays tiny and statically
// linkable into a scratch image.
package docker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Client is a thin wrapper around an *http.Client wired to the Docker socket.
type Client struct {
	http    *http.Client
	host    string // the scheme://host portion used to build URLs
	version string // pinned API version, e.g. "v1.43"
}

// New builds a client. If host is empty it honours DOCKER_HOST, then falls back
// to the default unix socket. Supported host forms:
//
//	unix:///var/run/docker.sock
//	/var/run/docker.sock           (bare path treated as unix socket)
//	tcp://1.2.3.4:2375
func New(host string) (*Client, error) {
	if host == "" {
		host = os.Getenv("DOCKER_HOST")
	}
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	var baseHost string
	allowInsecureRemote := envTrueAny("AMMIT_INSECURE_DOCKER_HOST", "CDEBUG_INSECURE_DOCKER_HOST")

	switch {
	case strings.HasPrefix(host, "unix://"), strings.HasPrefix(host, "/"):
		sockPath := strings.TrimPrefix(host, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", sockPath)
		}
		// The host part of the URL is irrelevant for unix sockets but must be
		// a valid, constant value.
		baseHost = "http://docker"
	case strings.HasPrefix(host, "tcp://"):
		proto := "https://"
		if allowInsecureRemote {
			proto = "http://"
		}
		baseHost = proto + strings.TrimPrefix(host, "tcp://")
	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		if strings.HasPrefix(host, "http://") && !allowInsecureRemote {
			return nil, fmt.Errorf("insecure Docker host %q blocked; use https:// or set AMMIT_INSECURE_DOCKER_HOST=1 to allow plain HTTP", host)
		}
		baseHost = host
	default:
		return nil, fmt.Errorf("unsupported DOCKER_HOST scheme: %q", host)
	}

	return &Client{
		http:    &http.Client{Transport: transport, Timeout: 30 * time.Second},
		host:    baseHost,
		version: "v1.43", // widely supported; daemon negotiates down gracefully
	}, nil
}

// get performs a GET against the API and decodes the JSON body into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.host + "/" + c.version + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting docker daemon: %w (is the socket mounted?)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("docker api %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ErrNotFound is returned when the daemon reports a 404 for a resource.
var ErrNotFound = fmt.Errorf("not found")

// Ping verifies the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	return c.get(ctx, "/_ping", nil, nil)
}

// ContainerSummary is a trimmed view of /containers/json entries.
type ContainerSummary struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

// List returns running containers (all=true includes stopped).
func (c *Client) List(ctx context.Context, all bool) ([]ContainerSummary, error) {
	q := url.Values{}
	if all {
		q.Set("all", "true")
	}
	var out []ContainerSummary
	err := c.get(ctx, "/containers/json", q, &out)
	return out, err
}

// Resolve turns a user-supplied name or short ID into a full container ID.
func (c *Client) Resolve(ctx context.Context, ref string) (ContainerSummary, error) {
	list, err := c.List(ctx, true)
	if err != nil {
		return ContainerSummary{}, err
	}
	return resolveFromList(list, ref)
}

func resolveFromList(list []ContainerSummary, ref string) (ContainerSummary, error) {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "/")
	if ref == "" {
		return ContainerSummary{}, fmt.Errorf("empty container reference")
	}

	matches := make([]ContainerSummary, 0, 4)
	seen := map[string]bool{}
	add := func(ct ContainerSummary) {
		if !seen[ct.ID] {
			seen[ct.ID] = true
			matches = append(matches, ct)
		}
	}

	for _, ct := range list {
		if ct.ID == ref {
			return ct, nil
		}
		if strings.HasPrefix(ct.ID, ref) {
			add(ct)
		}
		for _, n := range ct.Names {
			if strings.TrimPrefix(n, "/") == ref {
				add(ct)
				break
			}
		}
	}

	switch len(matches) {
	case 0:
		return ContainerSummary{}, fmt.Errorf("no container matching %q", ref)
	case 1:
		return matches[0], nil
	default:
		sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
		choices := make([]string, 0, len(matches))
		for _, m := range matches {
			choices = append(choices, fmt.Sprintf("%s(%s)", shortID(m.ID), firstName(m.Names)))
		}
		return ContainerSummary{}, fmt.Errorf("container reference %q is ambiguous; matches: %s", ref, strings.Join(choices, ", "))
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func firstName(names []string) string {
	if len(names) == 0 {
		return "unnamed"
	}
	return strings.TrimPrefix(names[0], "/")
}

func envTrue(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envTrueAny(primary, legacy string) bool {
	if envTrue(primary) {
		return true
	}
	return envTrue(legacy)
}

// Inspect returns the full inspection document for a container, decoded into
// the typed subset we use. Fields not modelled are ignored, keeping the client
// resilient to API drift.
func (c *Client) Inspect(ctx context.Context, id string) (*Inspection, error) {
	var out Inspection
	if err := c.get(ctx, "/containers/"+id+"/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stats fetches CPU/memory/IO/network usage. Because a single one-shot sample
// has an empty precpu block (making CPU% read as zero), we take two samples a
// short interval apart and stitch the first into the second's precpu fields so
// downstream CPU-delta maths is correct.
func (c *Client) Stats(ctx context.Context, id string) (*StatsSample, error) {
	first, err := c.statsOnce(ctx, id)
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}
	second, err := c.statsOnce(ctx, id)
	if err != nil {
		// Fall back to the first sample (CPU% may read low) rather than failing.
		return first, nil
	}
	second.PreCPUStats = first.CPUStats
	return second, nil
}

// statsOnce fetches a single non-streaming sample.
func (c *Client) statsOnce(ctx context.Context, id string) (*StatsSample, error) {
	q := url.Values{}
	q.Set("stream", "false")
	q.Set("one-shot", "true")
	var out StatsSample
	if err := c.get(ctx, "/containers/"+id+"/stats", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
