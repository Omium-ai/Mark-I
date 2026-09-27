package rm

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestRuntimeChildEnvCarriesNoSecret(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-daemon")
	t.Setenv("SECRET_X", "hunter2")
	p := testPlane(t, Config{})
	s := &slot{m: stubManifest("a")}
	cmd, err := p.child("/bin/llama-server", "/m.gguf", s).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") || strings.HasPrefix(kv, "SECRET_X=") {
			t.Fatalf("llama-server inherited %s", kv)
		}
	}
	if cmd.Env == nil || !slices.Contains(cmd.Env, "LLAMA_API_KEY="+*s.key.Load()) {
		t.Fatalf("the per-start key is not the child's: %v", cmd.Env)
	}
}
