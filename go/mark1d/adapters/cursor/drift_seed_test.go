package cursor

// The pre-Mark1 hooks.json the ADR-0014 drift tests start from (mechanism B: it exists).
const (
	driftTargetName = "hooks.json"
	driftSeedBody   = "{\n  \"version\": 1,\n  \"hooks\": {\"stop\": [ {\"command\": \"./audit.sh\", \"loop_limit\": 10} ]}\n}\n"
	driftSeedMarker = `"./audit.sh"`
)
