package supervise

import (
	"slices"
	"strings"
	"testing"
)

func TestChildEnvCarriesNoSecret(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-daemon")
	t.Setenv("SECRET_X", "hunter2")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws")
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/home/daemon")
	env := ChildEnv("HOME=/child", "LLAMA_API_KEY=k")
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k == "ANTHROPIC_API_KEY" || k == "SECRET_X" || k == "AWS_SECRET_ACCESS_KEY" {
			t.Fatalf("%s reached a supervised child: %v", k, env)
		}
	}
	for _, want := range []string{"PATH=/usr/bin", "HOME=/child", "LLAMA_API_KEY=k"} {
		if !slices.Contains(env, want) {
			t.Fatalf("%s missing from %v", want, env)
		}
	}
	if slices.Contains(env, "HOME=/home/daemon") {
		t.Fatalf("an override left the daemon's value beside it: %v", env)
	}
}

func TestProxyChildEnvCarriesNoAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-daemon")
	t.Setenv("SECRET_X", "hunter2")
	for _, kv := range childEnv("/h") {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") || strings.HasPrefix(kv, "SECRET_X=") {
			t.Fatalf("the proxy inherited %s", kv)
		}
	}
}
