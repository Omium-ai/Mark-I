package codex

// The pre-Mark1 hooks.json the ADR-0014 drift tests start from (mechanism B: it exists).
const (
	driftTargetName = "hooks.json"
	driftSeedBody   = "{\n  \"description\": \"mine\",\n  \"hooks\": {\"PreToolUse\": [ {\"matcher\":\"shell\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ]} ]}\n}\n"
	driftSeedMarker = `"echo hi"`
)
