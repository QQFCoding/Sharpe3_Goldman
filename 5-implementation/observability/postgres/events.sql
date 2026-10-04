CREATE OR REPLACE VIEW aicl_security_events AS
SELECT timestamp, event->>'tenant_id' AS tenant_id, event->>'agent_id' AS agent_id,
  event->>'workflow_id' AS workflow_id, event->>'operation' AS operation,
  event->>'resource_category' AS resource_category, event->>'resource' AS tool,
  event->>'effect' AS effect, event->>'trace_id' AS trace_id,
  event->'security'->>'decision' AS decision,
  event->'security'->>'policy_revision' AS policy_revision,
  event->'security'->>'threat_feed_revision' AS threat_feed_revision,
  event->'security'->'risk'->>'semantic_status' AS semantic_status,
  event->'security'->'risk'->>'risk_band' AS risk_band,
  ARRAY(SELECT jsonb_array_elements_text(event->'security'->'reason_codes')) AS reason_codes,
  ARRAY(SELECT jsonb_array_elements_text(event->'security'->'controls')) AS controls,
  COALESCE((event->'security'->'risk'->>'prompt_injection')::double precision,0) AS injection_risk,
  COALESCE((event->'security'->'risk'->>'task_alignment')::double precision,1) AS task_alignment,
  COALESCE((event->'security'->'risk'->>'data_exfiltration')::double precision,0) AS exfiltration_risk,
  COALESCE((event->>'budget_consumed')::double precision,0) AS credits,
  COALESCE((event->'latencies'->>'total')::double precision,0) AS latency,
  event->'latencies' AS latencies, event->>'source_category' AS source_category,
  COALESCE((event->>'delegation_depth')::integer,0) AS delegation_depth
FROM aicl_audit WHERE event->>'phase' = 'final';
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'aicl_grafana') THEN
    GRANT USAGE ON SCHEMA public TO aicl_grafana;
    GRANT SELECT ON aicl_security_events TO aicl_grafana;
  END IF;
END $$;
