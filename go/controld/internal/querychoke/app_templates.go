package querychoke

// The desktop app's read templates (internal/appapi consumer). Registered by init so this file is a pure addition to the closed set; loadFrom validates them exactly like v1Templates (boot refusal R4) and every sweep that walks the registry covers them.
func init() { v1Templates = append(v1Templates, appTemplates...) }

var appTemplates = []template{
	{
		// appapi GET /sessions (desktop spec §5.2): one row per session over [from, to]; project = SessionStart.workspace_id hex, capture_paths the protojson enum names; arrests are task-bearing GuardDecision rows (the `interventions` reading). ponytail: agent/project/cursor filters are applied by the handler over this window scan; push them into the template when a tenant's window outgrows the row limit.
		name:    "app_sessions",
		version: "app_sessions.v1",
		body: `SELECT e.session_id AS session_id,
       any(e.agent) AS agent,
       hex(base64Decode(maxIf(JSONExtractString(e.payload, 'workspace_id'), e.event_type = 'SessionStart'))) AS project,
       anyIf(JSONExtract(e.payload, 'capture_paths', 'Array(String)'), e.event_type = 'SessionStart') AS capture_paths,
       min(e.occurred_at) AS started_at,
       max(e.occurred_at) AS ended_at,
       sum(e.input_tokens)                AS tokens_in,
       sum(e.output_tokens)               AS tokens_out,
       sum(e.cache_read_input_tokens)     AS tokens_cache_read,
       sum(e.cache_creation_input_tokens) AS tokens_cache_create,
       uniqExactIf(e.task_id, e.event_type = 'TaskOpen') AS tasks,
       uniqExactIf(e.task_id, e.verdict = 'satisfied' AND e.verdict_stage IN ('certified', 'revised')) AS tasks_verified,
       countIf(e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000')) AS arrests,
       countIf(e.event_type = 'MemoryInjection') AS injections,
       countIf(e.event_type = 'RouteDecision')   AS route_decisions,
       sumIf(e.dropped_quantity, e.event_type = 'Dropped' AND e.dropped_durability_class = 'billing_grade') AS dropped_billing,
       max(e.checkpoint_seq) AS checkpoint_seq
FROM (SELECT event_id, session_id, task_id, occurred_at, event_type, agent, payload, verdict, verdict_stage,
             input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens,
             dropped_quantity, dropped_durability_class, checkpoint_seq
      FROM m1p_events
      WHERE {{tenant_pred}}
        AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
        AND session_id != toUUID('00000000-0000-0000-0000-000000000000')
      LIMIT 1 BY event_id) AS e
GROUP BY e.session_id
ORDER BY e.session_id DESC`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
	{
		// appapi GET /sessions/{id}: the task-grain ledger rows over [from, to] in causal (session_epoch, seq) order; the handler narrows to one session and folds attempts with tvo_task_window's rule. payload leaves the choke only as the typed fields the handler picks (desktop spec §5.2: never paths or excerpts).
		name:    "app_session_events",
		version: "app_session_events.v1",
		body: `SELECT event_id, session_id, task_id, session_epoch, seq, occurred_at, event_type, model,
       input_tokens + output_tokens + cache_creation_input_tokens + cache_read_input_tokens AS tokens,
       toFloat64(cost_usd) AS cost_usd,
       verdict, verdict_stage, noise_cert_id, bundle_seq, checkpoint_seq, payload
FROM m1p_events
WHERE {{tenant_pred}}
  AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
  AND session_id != toUUID('00000000-0000-0000-0000-000000000000')
  AND event_type IN ('SessionStart', 'SessionEnd', 'TaskOpen', 'TaskClose', 'Usage', 'VerdictEvent', 'AnchorVote', 'GuardDecision', 'MemoryInjection', 'RouteDecision', 'ReceiptCheckpoint')
ORDER BY session_id, session_epoch, seq, event_id
LIMIT 1 BY event_id`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: maxRowLimit,
		timeout:  timeoutReport,
	},
	{
		// appapi GET /moments (desktop spec §5.1): arrests (task-bearing GuardDecision), injections and route decisions over [from, to], newest first; the handler cuts at ?since.
		name:    "app_moments",
		version: "app_moments.v1",
		body: `SELECT event_id, occurred_at, session_id, task_id, agent, event_type, propensity, fidelity, bundle_seq, payload
FROM m1p_events
WHERE {{tenant_pred}}
  AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
  AND event_type IN ('GuardDecision', 'MemoryInjection', 'RouteDecision')
  AND (event_type != 'GuardDecision' OR task_id != toUUID('00000000-0000-0000-0000-000000000000'))
ORDER BY occurred_at DESC, event_id DESC
LIMIT 1 BY event_id`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
}
