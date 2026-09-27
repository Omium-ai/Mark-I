package cortex

import (
	"context"
	"strings"
	"testing"
)

func TestCortexdChildEnvCarriesNoSecret(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-daemon")
	t.Setenv("SECRET_X", "hunter2")
	p, err := New(Config{StateDir: t.TempDir(), Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := p.child("/bin/cortexd", t.TempDir()).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Env == nil {
		t.Fatal("cortexd inherits the daemon's whole environment")
	}
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") || strings.HasPrefix(kv, "SECRET_X=") {
			t.Fatalf("cortexd inherited %s", kv)
		}
	}
}
