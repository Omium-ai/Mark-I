package querychoke

// The desktop app's read templates (internal/appapi consumer). Registered by init so this file is a pure addition to the closed set; loadFrom validates them exactly like v1Templates (boot refusal R4) and every sweep that walks the registry covers them.
func init() { v1Templates = append(v1Templates, appTemplates...) }

// savingsWindow is savings.v3's per-task inputs as window columns over the same scan (doc 16 ruling 4): the task's first block inside [from, to], and its terminal verdict's word, stage and posterior over everything the scan read — a template whose scan runs past `to` resolves a window's blocks with verdicts that landed after it (ADR-0013).
const savingsWindow = `minIf(occurred_at, event_type = 'GuardDecision' AND JSONExtractString(payload, 'reason_code') = 'stop_gate_block' AND toDate(occurred_at) <= {to:Date}) OVER (PARTITION BY task_id) AS first_block,
             argMaxIf(verdict, (session_epoch, seq), verdict != '') OVER (PARTITION BY task_id) AS t_word,
             argMaxIf(verdict_stage, (session_epoch, seq), verdict != '') OVER (PARTITION BY task_id) AS t_stage,
             argMaxIf((p_satisfied, p_violated, p_refused, p_error), (session_epoch, seq), verdict != '') OVER (PARTITION BY task_id) AS t_p`

// savingsResolved is live.go resolvedWord(...) == "satisfied": a certified or revised satisfied|violated word stands, else the posterior's mode (ties to the earlier of satisfied, violated, refused, error).
const savingsResolved = `if(e.t_word IN ('satisfied', 'violated') AND e.t_stage IN ('certified', 'revised'), e.t_word = 'satisfied', tupleElement(e.t_p, 1) > 0 AND tupleElement(e.t_p, 1) >= greatest(tupleElement(e.t_p, 2), tupleElement(e.t_p, 3), tupleElement(e.t_p, 4)))`

// savingsNet is live.go foldSavings' net in SQL: a block inside [from, to] on a task that resolved credits its estimate, usage after the first such block of a task that did not debits (through the end of the scan); arrests are never in it.
const savingsNet = `toInt64(sumIf(JSONExtractUInt(e.payload, 'tokens_saved_estimate'), e.event_type = 'GuardDecision' AND toDate(e.occurred_at) <= {to:Date} AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND JSONExtractString(e.payload, 'reason_code') = 'stop_gate_block' AND ` + savingsResolved + `))
       - toInt64(sumIf(e.tokens, e.event_type = 'Usage' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND e.first_block > toDateTime64(0, 3) AND e.occurred_at > e.first_block AND NOT ` + savingsResolved + `)) AS tokens_saved`

var appTemplates = []template{
	{
		// appapi GET /sessions (desktop spec §5.2): one row per session over [from, to]; project = SessionStart.workspace_id hex, capture_paths the protojson enum names; arrests are task-bearing GuardDecision rows (the `interventions` reading); history_import marks a session the tailer imported from transcript history (its history_import CoverageTransition, stamped at import time, is kept out of started_at/ended_at). arrests/blocks are the verify plane's GuardDecision rows on a task (policy.proto: knee_arrest, stop_gate_block); tokens_saved is savings.v3's net over the session's tasks (doc 16 ruling 4, may be negative; the scan ends today, so every verdict the ledger holds resolves it), so Sessions agrees with Reports and Home. tasks_verified counts tasks whose TERMINAL verdict's posterior MODE is satisfied (the rollup's rule, so Home's verified tile and the TVO denominator agree): the Chow band withholds the satisfied WORD below 8/9 (bootstrap rows top out near 0.7, 06 §3.1), so the wire says refused for a task every anchor passed — the outcome count is the evidence, the certificate is the trail's. A session that never counted a token, opened a task or drew a decision (a hook-only session outside every enabled root, a proxy handshake) is not listed: 122 of the founder's 141 rows were such. ponytail: agent/project/cursor filters are applied by the handler over this window scan; push them into the template when a tenant's window outgrows the row limit.
		name:    "app_sessions",
		version: "app_sessions.v10",
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
       uniqExactIf(e.task_id, e.event_type = 'VerdictEvent' AND (e.session_epoch, e.seq) = e.last_key AND e.p_satisfied > greatest(e.p_violated, e.p_refused, e.p_error)) AS tasks_verified,
       countIf(e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND JSONExtractString(e.payload, 'reason_code') IN ('knee_arrest', 'block_cap')) AS arrests,
       countIf(e.event_type = 'GuardDecision' AND e.task_id != toUUID('00000000-0000-0000-0000-000000000000') AND JSONExtractString(e.payload, 'reason_code') = 'stop_gate_block') AS blocks,
       ` + savingsNet + `,
       countIf(e.event_type = 'MemoryInjection') AS injections,
       countIf(e.event_type = 'RouteDecision')   AS route_decisions,
       sumIf(e.dropped_quantity, e.event_type = 'Dropped' AND e.dropped_durability_class = 'billing_grade') AS dropped_billing,
       max(e.checkpoint_seq) AS checkpoint_seq
FROM (SELECT event_id, session_id, task_id, occurred_at, event_type, agent, payload, verdict, verdict_stage,
             session_epoch, seq, p_satisfied, p_violated, p_refused, p_error,
             maxIf((session_epoch, seq), event_type = 'VerdictEvent') OVER (PARTITION BY session_id, task_id) AS last_key,
             input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens,
             input_tokens + output_tokens + cache_read_input_tokens + cache_creation_input_tokens AS tokens,
             ` + savingsWindow + `,
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
		devices:  true,
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
		devices:  true,
		rowLimit: maxRowLimit,
		timeout:  timeoutReport,
	},
	{
		// appapi GET /moments (desktop spec §5.1): arrests (task-bearing GuardDecision), injections and route decisions over [from, to], newest first; the handler cuts at ?since. agent is the session's SessionStart agent when that row is in the window, else the row's own stamp (chproj: SdkInfo.agent when the SessionStart was in an earlier batch).
		// v3 keeps a single-rung advisory "stay" (every request of a subscription session) out of the feed: a decision, not a moment — 1,628 of them buried the founder's four blocks below the feed's newest hundred.
		name:    "app_moments",
		version: "app_moments.v3",
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
              AND (event_type != 'RouteDecision' OR fidelity != 'advisory' OR JSONLength(payload, 'candidates') > 1)
            LIMIT 1 BY event_id) AS d) AS e
WHERE e.event_type != 'SessionStart'
ORDER BY e.occurred_at DESC, e.event_id DESC`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		devices:  true,
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
	{
		// appapi GET /team per-member totals (16-release L3) and intel digest.weekly: aggregates per device over [from, to], read only under TenantWide; controld maps device to member in Postgres and never answers a device id. sessions/tasks_verified/tokens follow app_sessions' rules inside [from, to]; tokens_saved is savings.v3's net over the blocks inside [from, to], resolved by every verdict and debited by every post-block usage the ledger holds through today (ADR-0013: a weekly digest's Sunday block still resolves on Monday's verdict).
		name:    "team_device_totals",
		version: "team_device_totals.v2",
		body: `SELECT e.device_id AS device_id,
       uniqExactIf(e.session_id, e.in_window AND e.session_id != toUUID('00000000-0000-0000-0000-000000000000') AND (e.tokens > 0 OR e.event_type = 'TaskOpen')) AS sessions,
       uniqExactIf(e.task_id, e.in_window AND e.event_type = 'VerdictEvent' AND (e.session_epoch, e.seq) = e.last_key AND e.p_satisfied > greatest(e.p_violated, e.p_refused, e.p_error)) AS tasks_verified,
       sumIf(e.tokens, e.in_window) AS tokens,
       ` + savingsNet + `
FROM (SELECT event_id, device_id, session_id, task_id, occurred_at, event_type, payload, verdict, verdict_stage, session_epoch, seq, p_satisfied, p_violated, p_refused, p_error,
             toDate(occurred_at) <= {to:Date} AS in_window,
             maxIf((session_epoch, seq), event_type = 'VerdictEvent' AND toDate(occurred_at) <= {to:Date}) OVER (PARTITION BY session_id, task_id) AS last_key,
             input_tokens + output_tokens + cache_read_input_tokens + cache_creation_input_tokens AS tokens,
             ` + savingsWindow + `
      FROM m1p_events
      WHERE {{tenant_pred}}
        AND toDate(occurred_at) >= {from:Date}
      LIMIT 1 BY event_id) AS e
GROUP BY e.device_id
HAVING countIf(e.in_window) > 0
ORDER BY e.device_id`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
}
