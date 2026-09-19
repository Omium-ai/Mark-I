package adapters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookShapeNamesTheMissingVendorField(t *testing.T) {
	state := t.TempDir()
	if err := HookShape(state, "gemini"); err != nil {
		t.Fatalf("no shape files must be silent, got %v", err)
	}
	keys := map[string]string{"hook_event_name": "string", "session_id": "string", "tool_name": "string"}
	if err := WriteShape(state, "gemini", "BeforeTool", keys, nil); err != nil {
		t.Fatal(err)
	}
	if err := HookShape(state, "gemini"); err != nil {
		t.Fatalf("complete shape must pass, got %v", err)
	}
	if err := WriteShape(state, "gemini", "AfterTool", keys, []string{"tool_name"}); err != nil {
		t.Fatal(err)
	}
	err := HookShape(state, "gemini")
	if err == nil || !strings.Contains(err.Error(), "AfterTool") || !strings.Contains(err.Error(), "tool_name") {
		t.Fatalf("want the event and the renamed key named, got %v", err)
	}
	if err := HookShape(state, "codex"); err != nil {
		t.Fatalf("another agent's shape must not leak, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(state, "shape", "gemini", "AfterTool.json"), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := HookShape(state, "gemini"); err != nil {
		t.Fatalf("a torn shape file is skipped, got %v", err)
	}
}
