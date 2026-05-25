package docker

import (
	"strings"
	"testing"
)

func TestNewBlocksInsecureHTTPHostByDefault(t *testing.T) {
	t.Setenv("AMMIT_INSECURE_DOCKER_HOST", "")
	_, err := New("http://127.0.0.1:2375")
	if err == nil {
		t.Fatal("expected insecure host to be blocked")
	}
	if !strings.Contains(err.Error(), "AMMIT_INSECURE_DOCKER_HOST") {
		t.Fatalf("expected opt-in guidance in error, got %v", err)
	}
}

func TestNewTCPDefaultsToHTTPS(t *testing.T) {
	t.Setenv("AMMIT_INSECURE_DOCKER_HOST", "")
	c, err := New("tcp://1.2.3.4:2376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := c.host, "https://1.2.3.4:2376"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
}

func TestNewTCPCanOptIntoHTTP(t *testing.T) {
	t.Setenv("AMMIT_INSECURE_DOCKER_HOST", "1")
	c, err := New("tcp://1.2.3.4:2375")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := c.host, "http://1.2.3.4:2375"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
}

func TestNewLegacyEnvCanOptIntoHTTP(t *testing.T) {
	t.Setenv("AMMIT_INSECURE_DOCKER_HOST", "")
	t.Setenv("CDEBUG_INSECURE_DOCKER_HOST", "1")
	c, err := New("tcp://1.2.3.4:2375")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := c.host, "http://1.2.3.4:2375"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
}

func TestResolveFromListAmbiguousPrefix(t *testing.T) {
	list := []ContainerSummary{
		{ID: "abc1111111111111111111111111111111111111111111111111111111111111", Names: []string{"/api-1"}},
		{ID: "abc2222222222222222222222222222222222222222222222222222222222222", Names: []string{"/api-2"}},
	}

	_, err := resolveFromList(list, "abc")
	if err == nil {
		t.Fatal("expected ambiguous match error")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous in error, got %v", err)
	}
}

func TestResolveFromListByName(t *testing.T) {
	list := []ContainerSummary{
		{ID: "abc1111111111111111111111111111111111111111111111111111111111111", Names: []string{"/api"}},
		{ID: "def2222222222222222222222222222222222222222222222222222222222222", Names: []string{"/worker"}},
	}

	ct, err := resolveFromList(list, "worker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := ct.ID, list[1].ID; got != want {
		t.Fatalf("id = %q, want %q", got, want)
	}
}
