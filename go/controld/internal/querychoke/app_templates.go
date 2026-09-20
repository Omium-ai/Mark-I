package querychoke

// The desktop app's read templates (internal/appapi consumer). Registered by init so this file is a pure addition to the closed set; loadFrom validates them exactly like v1Templates (boot refusal R4) and every sweep that walks the registry covers them.
func init() { v1Templates = append(v1Templates, appTemplates...) }

var appTemplates = []template{
	{
		// appapi GET /sessions (desktop spec §5.2): one row per session over [from, to]; project = SessionStart.workspace_id hex, capture_paths the protojson enum names; arrests are task-bearing GuardDecision rows (the `interventions` reading); history_import marks a session the tailer imported from transcript history (its history_import CoverageTransition, stamped at import time, is kept out of started_at/ended_at). arrests/blocks/tokens_saved are the verify plane's GuardDecision rows on a task (policy.proto: knee_arrest, stop_gate_block, tokens_saved_estimate). tasks_verified counts tasks with a verdict whose posterior MODE is satisfied: the Chow band withholds the satisfied WORD below 8/9 (bootstrap rows top out near 0.7, 06 §3.1), so the wire says refused for a task every anchor passed — the outcome count is the evidence, the certificate is the trail's. A session that never counted a token, opened a task or drew a decision (a hook-only session outside every enabled root, a proxy handshake) is not listed: 122 of the founder's 141 rows were such. ponytail: agent/project/cursor filters are applied by the handler over this window scan; push them into the template when a tenant's window outgrows the row limit.
		name:    "app_sessions",
		version: "app_sessions.v6",
		body: `SELECT e.session_id AS session_id,
       coalesce(nullIf(anyIf(JSONExtractString(e.payload, 'agent'), e.event_type = 'SessionStart'), ''), anyIf(e.agent, e.agent != '')) AS agent,
       hex(base64Decode(maxIf(JSONExtractString(e.payload, 'workspace_id'), e.event_type = 'SessionStart'))) AS project,
       anyIf(JSONExtract(e.payload, 'capture_paths', 'Array(String)'), e.event_type = 'SessionStart') AS capture_paths,
       minIf(e.occurred_at, e.event_type != 'CoverageTransition') AS started_at,
       maxIf(e.occurred_at, e.event_type != 'CoverageTransition') AS ended_at,
       countIf(e.event_type = 'CoverageTransition' AND JSONExtractString(e.payload, 'reason_code') = 'history_import') > 0 AS history_import,
       sum(e.input_tokens)                AS tokens_in,
       sum(e.output_tokens)               AS tokens_out,
       sum(e.cache_read_input_tokens)     AS tokens_cache_read,
       sum(e.cache_creation_input_tokens) AS tokens_cache_create,
       uniqExactIf(e.task_id, e.event_type = 'TaskOpen') AS tasks,
       uniqExactIf(e.task_id, e.event_type = 'VerdictEvent' AND e.p_satisfied > greatest(e.p_violated, e.p_refused, e.p_error)) AS tasks_verified,
       countIf(e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND JSONExtractString(e.payload, 'reason_code') = 'knee_arrest') AS arrests,
       countIf(e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND JSONExtractString(e.payload, 'reason_code') = 'stop_gate_block') AS blocks,
       sumIf(JSONExtractUInt(e.payload, 'tokens_saved_estimate'), e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000')) AS tokens_saved,
       countIf(e.event_type = 'MemoryInjection') AS injections,
       countIf(e.event_type = 'RouteDecision')   AS route_decisions,
       sumIf(e.dropped_quantity, e.event_type = 'Dropped' AND e.dropped_durability_class = 'billing_grade') AS dropped_billing,
       max(e.checkpoint_seq) AS checkpoint_seq
FROM (SELECT event_id, session_id, task_id, occurred_at, event_type, agent, payload, verdict, verdict_stage,
             p_satisfied, p_violated, p_refused, p_error,
             input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens,
             dropped_quantity, dropped_durability_class, checkpoint_seq
      FROM m1p_events
      WHERE {{tenant_pred}}
        AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
        AND session_id != toUUID('00000000-0000-0000-0000-000000000000')
      LIMIT 1 BY event_id) AS e
GROUP BY e.session_id
HAVING tokens_in + tokens_out + tokens_cache_read + tokens_cache_create > 0 OR tasks > 0 OR arrests > 0 OR blocks > 0
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
		// appapi GET /moments (desktop spec §5.1): arrests (task-bearing GuardDecision), injections and route decisions over [from, to], newest first; the handler cuts at ?since. agent is the session's SessionStart agent when that row is in the window, else the row's own stamp (chproj: SdkInfo.agent when the SessionStart was in an earlier batch).
		name:    "app_moments",
		version: "app_moments.v2",
		body: `SELECT e.event_id AS event_id, e.occurred_at AS occurred_at, e.session_id AS session_id, e.task_id AS task_id,
       if(e.start_agent != '', e.start_agent, e.agent) AS agent,
       e.event_type AS event_type, e.propensity AS propensity, e.fidelity AS fidelity, e.bundle_seq AS bundle_seq, e.payload AS payload
FROM (SELECT event_id, occurred_at, session_id, task_id, agent, event_type, propensity, fidelity, bundle_seq, payload,
             anyIf(JSONExtractString(payload, 'agent'), event_type = 'SessionStart') OVER (PARTITION BY session_id) AS start_agent
      FROM (SELECT event_id, occurred_at, session_id, task_id, agent, event_type, propensity, fidelity, bundle_seq, payload
            FROM m1p_events
            WHERE {{tenant_pred}}
              AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
              AND event_type IN ('SessionStart', 'GuardDecision', 'MemoryInjection', 'RouteDecision')
              AND (event_type != 'GuardDecision' OR task_id != toUUID('00000000-0000-0000-0000-000000000000'))
            LIMIT 1 BY event_id) AS d) AS e
WHERE e.event_type != 'SessionStart'
ORDER BY e.occurred_at DESC, e.event_id DESC`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
}
