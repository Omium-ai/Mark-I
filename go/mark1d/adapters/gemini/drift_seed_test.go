package gemini

// The pre-Mark1 settings.json the ADR-0014 drift tests start from.
const (
	driftTargetName = "settings.json"
	driftSeedBody   = "{\n  \"security\": {\"auth\": {\"selectedType\": \"oauth-personal\"}}\n}\n"
	driftSeedMarker = `"oauth-personal"`
)
